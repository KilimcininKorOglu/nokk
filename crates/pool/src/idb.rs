//! IndexedDB storage, shared by every isolate thread of the process.
//!
//! The page-facing objects (`IDBDatabase`, `IDBTransaction`, requests,
//! cursors, events) live in JS; this module owns the data and does all the
//! per-record work: key validation and ordering, key paths, indexes,
//! structured clone (V8's serializer, the same format and errors as Chrome),
//! and the undo log that makes an aborted transaction leave no trace.
//!
//! Layout: partition (one per profile: identity or session) -> (origin,
//! database name) -> database. A database is one `RwLock`: reads of
//! read-only transactions on different threads run side by side. Keys are
//! stored encoded so that byte order is IndexedDB key order; ranges, cursors
//! and unique checks are `BTreeMap`/`BTreeSet` range queries, O(log n) to
//! reach a position.
//!
//! Errors are thrown into JS as `[name, message]`; the JS side turns them
//! into `DOMException`s with Chrome's "Failed to execute ..." prefix.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use v8::{ValueDeserializerHelper, ValueSerializerHelper};

// ---- keys ------------------------------------------------------------------

/// An IndexedDB key, as the spec orders them: number < date < string <
/// binary < array.
#[derive(Clone, Debug, PartialEq)]
pub enum Key {
    Num(f64),
    Date(f64),
    Str(Vec<u16>),
    Bin(Vec<u8>),
    Arr(Vec<Key>),
}

const T_END: u8 = 0x00;
const T_NUM: u8 = 0x10;
const T_DATE: u8 = 0x20;
const T_STR: u8 = 0x30;
const T_BIN: u8 = 0x40;
const T_ARR: u8 = 0x50;

/// Order-preserving bits of a double: negative numbers inverted, positive
/// ones with the sign bit set. -0 is 0, as IndexedDB compares them.
fn num_bits(x: f64) -> [u8; 8] {
    let x = if x == 0.0 { 0.0 } else { x };
    let b = x.to_bits();
    let o = if b >> 63 == 1 { !b } else { b | (1 << 63) };
    o.to_be_bytes()
}

fn num_from_bits(b: [u8; 8]) -> f64 {
    let o = u64::from_be_bytes(b);
    let bits = if o >> 63 == 1 { o & !(1 << 63) } else { !o };
    f64::from_bits(bits)
}

/// Bytes with 0x00 escaped as 0x00 0xFF and a 0x00 0x00 terminator: byte
/// order stays the order of the original, and a prefix sorts first.
fn put_escaped(out: &mut Vec<u8>, bytes: impl Iterator<Item = u8>) {
    for b in bytes {
        out.push(b);
        if b == 0 {
            out.push(0xFF);
        }
    }
    out.push(0);
    out.push(0);
}

impl Key {
    /// The encoded form. Self-delimiting, so an index entry can be the index
    /// key followed by the primary key and still sort by both.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Key::Num(x) => {
                out.push(T_NUM);
                out.extend_from_slice(&num_bits(*x));
            }
            Key::Date(x) => {
                out.push(T_DATE);
                out.extend_from_slice(&num_bits(*x));
            }
            Key::Str(units) => {
                out.push(T_STR);
                put_escaped(out, units.iter().flat_map(|u| u.to_be_bytes()));
            }
            Key::Bin(bytes) => {
                out.push(T_BIN);
                put_escaped(out, bytes.iter().copied());
            }
            Key::Arr(items) => {
                out.push(T_ARR);
                for k in items {
                    k.encode_into(out);
                }
                out.push(T_END);
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Key> {
        let mut pos = 0;
        let k = Self::decode_at(bytes, &mut pos)?;
        Some(k)
    }

    fn decode_at(b: &[u8], pos: &mut usize) -> Option<Key> {
        let tag = *b.get(*pos)?;
        *pos += 1;
        let unescape = |b: &[u8], pos: &mut usize| -> Option<Vec<u8>> {
            let mut out = Vec::new();
            loop {
                let x = *b.get(*pos)?;
                *pos += 1;
                if x == 0 {
                    let y = *b.get(*pos)?;
                    *pos += 1;
                    if y == 0 {
                        return Some(out);
                    }
                    out.push(0);
                } else {
                    out.push(x);
                }
            }
        };
        match tag {
            T_NUM | T_DATE => {
                let raw: [u8; 8] = b.get(*pos..*pos + 8)?.try_into().ok()?;
                *pos += 8;
                let x = num_from_bits(raw);
                Some(if tag == T_NUM { Key::Num(x) } else { Key::Date(x) })
            }
            T_STR => {
                let raw = unescape(b, pos)?;
                Some(Key::Str(raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()))
            }
            T_BIN => Some(Key::Bin(unescape(b, pos)?)),
            T_ARR => {
                let mut items = Vec::new();
                loop {
                    if *b.get(*pos)? == T_END {
                        *pos += 1;
                        return Some(Key::Arr(items));
                    }
                    items.push(Self::decode_at(b, pos)?);
                }
            }
            _ => None,
        }
    }

    /// Length of the encoded key at the start of `b` (index entries are key
    /// then primary key).
    fn encoded_len(b: &[u8]) -> Option<usize> {
        let mut pos = 0;
        Self::decode_at(b, &mut pos)?;
        Some(pos)
    }
}

/// "Convert a value to a key", with the spec's cycle check for arrays.
pub fn key_from_value<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    v: v8::Local<'s, v8::Value>,
    seen: &mut Vec<v8::Local<'s, v8::Value>>,
) -> Option<Key> {
    if v.is_number() {
        let x = v.number_value(scope)?;
        return if x.is_nan() { None } else { Some(Key::Num(x)) };
    }
    if v.is_string() {
        let s = v8::Local::<v8::String>::try_from(v).ok()?;
        let mut buf = vec![0u16; s.length()];
        s.write_v2(scope, 0, &mut buf, v8::WriteFlags::empty());
        return Some(Key::Str(buf));
    }
    if v.is_date() {
        let d = v8::Local::<v8::Date>::try_from(v).ok()?;
        let x = d.value_of();
        return if x.is_nan() { None } else { Some(Key::Date(x)) };
    }
    if v.is_array_buffer() {
        let ab = v8::Local::<v8::ArrayBuffer>::try_from(v).ok()?;
        if ab.was_detached() {
            return None;
        }
        let len = ab.byte_length();
        let mut out = vec![0u8; len];
        if len > 0 {
            if let Some(p) = ab.data() {
                // SAFETY: `len` bytes live behind `data` while `ab` is held.
                unsafe { std::ptr::copy_nonoverlapping(p.as_ptr() as *const u8, out.as_mut_ptr(), len) };
            }
        }
        return Some(Key::Bin(out));
    }
    if v.is_array_buffer_view() {
        let view = v8::Local::<v8::ArrayBufferView>::try_from(v).ok()?;
        let mut out = vec![0u8; view.byte_length()];
        view.copy_contents(&mut out);
        return Some(Key::Bin(out));
    }
    if v.is_array() {
        if seen.iter().any(|s| s.strict_equals(v)) {
            return None;
        }
        let arr = v8::Local::<v8::Array>::try_from(v).ok()?;
        let len = arr.length();
        seen.push(v);
        let mut items = Vec::with_capacity(len as usize);
        for i in 0..len {
            let name = v8::String::new(scope, &i.to_string()).unwrap();
            let has = arr.has_own_property(scope, name.into()).unwrap_or(false);
            if !has {
                seen.pop();
                return None;
            }
            let item = arr.get_index(scope, i)?;
            let k = key_from_value(scope, item, seen);
            match k {
                Some(k) => items.push(k),
                None => {
                    seen.pop();
                    return None;
                }
            }
        }
        seen.pop();
        return Some(Key::Arr(items));
    }
    None
}

/// A key from any value handle (re-rooted in `scope`).
pub fn to_key(scope: &mut v8::PinScope, v: v8::Local<v8::Value>) -> Option<Key> {
    let v = v8::Local::new(scope, v);
    key_from_value(scope, v, &mut Vec::new())
}

pub fn key_to_value<'s>(scope: &mut v8::PinScope<'s, '_>, k: &Key) -> v8::Local<'s, v8::Value> {
    match k {
        Key::Num(x) => v8::Number::new(scope, *x).into(),
        Key::Date(x) => v8::Date::new(scope, *x).map(Into::into).unwrap_or_else(|| v8::undefined(scope).into()),
        Key::Str(u) => v8::String::new_from_two_byte(scope, u, v8::NewStringType::Normal)
            .map(Into::into)
            .unwrap_or_else(|| v8::undefined(scope).into()),
        Key::Bin(b) => {
            let store = v8::ArrayBuffer::new_backing_store_from_vec(b.clone()).make_shared();
            v8::ArrayBuffer::with_backing_store(scope, &store).into()
        }
        Key::Arr(items) => {
            let vals: Vec<v8::Local<v8::Value>> = items.iter().map(|k| key_to_value(scope, k)).collect();
            v8::Array::new_with_elements(scope, &vals).into()
        }
    }
}

// ---- key paths ---------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum KeyPath {
    None,
    Str(String),
    Arr(Vec<String>),
}

impl KeyPath {
    fn from_value(scope: &mut v8::PinScope, v: v8::Local<v8::Value>) -> KeyPath {
        if v.is_null_or_undefined() {
            return KeyPath::None;
        }
        if v.is_array() {
            let arr = v8::Local::<v8::Array>::try_from(v).unwrap();
            let mut out = Vec::new();
            for i in 0..arr.length() {
                let item = arr.get_index(scope, i).unwrap_or_else(|| v8::undefined(scope).into());
                out.push(item.to_rust_string_lossy(scope));
            }
            return KeyPath::Arr(out);
        }
        KeyPath::Str(v.to_rust_string_lossy(scope))
    }

    fn to_value<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
        match self {
            KeyPath::None => v8::null(scope).into(),
            KeyPath::Str(s) => v8::String::new(scope, s).unwrap().into(),
            KeyPath::Arr(a) => {
                let vals: Vec<v8::Local<v8::Value>> =
                    a.iter().map(|s| v8::String::new(scope, s).unwrap().into()).collect();
                v8::Array::new_with_elements(scope, &vals).into()
            }
        }
    }
}

/// "Evaluate a key path on a value": own properties only, plus the length
/// of strings and arrays. Runs on the clone, so no page code can run.
fn eval_path<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    path: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    if path.is_empty() {
        return Some(value);
    }
    let mut cur = value;
    for ident in path.split('.') {
        if ident == "length" && (cur.is_string() || cur.is_array()) {
            let n = if cur.is_string() {
                v8::Local::<v8::String>::try_from(cur).ok()?.length() as f64
            } else {
                v8::Local::<v8::Array>::try_from(cur).ok()?.length() as f64
            };
            cur = v8::Number::new(scope, n).into();
            continue;
        }
        if !cur.is_object() {
            return None;
        }
        let obj = cur.to_object(scope)?;
        let name = v8::String::new(scope, ident)?;
        if !obj.has_own_property(scope, name.into()).unwrap_or(false) {
            return None;
        }
        cur = obj.get(scope, name.into())?;
    }
    Some(cur)
}

/// The key a key path yields, or `Err(())` when it yields something that is
/// not a key, `Ok(None)` when it yields nothing.
fn key_at_path<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    path: &KeyPath,
) -> Result<Option<Key>, ()> {
    match path {
        KeyPath::None => Ok(None),
        KeyPath::Str(p) => match eval_path(scope, value, p) {
            None => Ok(None),
            Some(v) => to_key(scope, v).map(Some).ok_or(()),
        },
        KeyPath::Arr(ps) => {
            let mut items = Vec::with_capacity(ps.len());
            for p in ps {
                let v = eval_path(scope, value, p).ok_or(())?;
                items.push(to_key(scope, v).ok_or(())?);
            }
            Ok(Some(Key::Arr(items)))
        }
    }
}

/// Index keys of a value: none when the path yields no valid key; for a
/// multi-entry index over an array, each distinct valid element.
fn index_keys<'s>(scope: &mut v8::PinScope<'s, '_>, value: v8::Local<'s, v8::Value>, ix: &IndexMeta) -> Vec<Vec<u8>> {
    if ix.multi {
        if let KeyPath::Str(p) = &ix.key_path {
            let Some(v) = eval_path(scope, value, p) else { return Vec::new() };
            if v.is_array() {
                let arr = v8::Local::<v8::Array>::try_from(v).unwrap();
                let mut set = BTreeSet::new();
                for i in 0..arr.length() {
                    let Some(item) = arr.get_index(scope, i) else { continue };
                    if let Some(k) = to_key(scope, item) {
                        set.insert(k.encode());
                    }
                }
                return set.into_iter().collect();
            }
            return to_key(scope, v).map(|k| vec![k.encode()]).unwrap_or_default();
        }
    }
    match key_at_path(scope, value, &ix.key_path) {
        Ok(Some(k)) => vec![k.encode()],
        _ => Vec::new(),
    }
}

// ---- structured clone --------------------------------------------------------

struct CloneDelegate {
    error: std::cell::RefCell<Option<String>>,
}

impl v8::ValueSerializerImpl for CloneDelegate {
    fn throw_data_clone_error<'s>(&self, scope: &mut v8::PinScope<'s, '_>, message: v8::Local<'s, v8::String>) {
        *self.error.borrow_mut() = Some(message.to_rust_string_lossy(scope));
        let exc = v8::Exception::error(scope, message);
        scope.throw_exception(exc);
    }
}

struct ReadDelegate;
impl v8::ValueDeserializerImpl for ReadDelegate {}

/// Structured clone to bytes; `Err(message)` is V8's DataCloneError text.
pub fn serialize(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> Result<Vec<u8>, String> {
    let delegate = Box::new(CloneDelegate { error: std::cell::RefCell::new(None) });
    let err_cell: *const std::cell::RefCell<Option<String>> = &delegate.error;
    v8::tc_scope!(let tc, scope);
    let ser = v8::ValueSerializer::new(tc, delegate);
    ser.write_header();
    let context = tc.get_current_context();
    let ok = ser.write_value(context, value);
    if ok == Some(true) {
        return Ok(ser.release());
    }
    // SAFETY: the delegate lives inside `ser`, which is still alive here.
    let msg = unsafe { (*err_cell).borrow().clone() };
    if tc.has_caught() {
        tc.reset();
    }
    Err(msg.unwrap_or_else(|| "The object could not be cloned.".to_string()))
}

pub fn deserialize<'s>(scope: &mut v8::PinScope<'s, '_>, bytes: &[u8]) -> v8::Local<'s, v8::Value> {
    let de = v8::ValueDeserializer::new(scope, Box::new(ReadDelegate), bytes);
    let context = scope.get_current_context();
    if de.read_header(context) != Some(true) {
        return v8::undefined(scope).into();
    }
    de.read_value(context).unwrap_or_else(|| v8::undefined(scope).into())
}

// ---- the store -------------------------------------------------------------

#[derive(Clone, Debug)]
struct IndexMeta {
    id: u32,
    name: String,
    key_path: KeyPath,
    unique: bool,
    multi: bool,
}

struct Index {
    meta: IndexMeta,
    /// Index key ++ primary key, both encoded.
    entries: BTreeSet<Vec<u8>>,
}

#[derive(Clone)]
struct Record {
    value: Arc<Vec<u8>>,
    /// (index id, index keys) for every index of the store.
    ikeys: Vec<(u32, Vec<Vec<u8>>)>,
}

struct Store {
    id: u32,
    name: String,
    key_path: KeyPath,
    auto_inc: bool,
    /// The key generator's current number.
    next: f64,
    records: BTreeMap<Vec<u8>, Record>,
    indexes: Vec<Index>,
}

#[derive(Default)]
struct DbData {
    version: u64,
    stores: Vec<Store>,
    next_id: u32,
}

impl DbData {
    fn store(&self, name: &str) -> Option<&Store> {
        self.stores.iter().find(|s| s.name == name)
    }
    fn store_mut(&mut self, name: &str) -> Option<&mut Store> {
        self.stores.iter_mut().find(|s| s.name == name)
    }
}

enum Undo {
    Record { store: u32, key: Vec<u8>, old: Option<Record> },
    KeyGen { store: u32, old: f64 },
    Cleared { store: u32, records: BTreeMap<Vec<u8>, Record> },
    StoreCreated(u32),
    StoreDeleted(Store),
    StoreRenamed { store: u32, old: String },
    IndexCreated { store: u32, index: u32 },
    IndexDeleted { store: u32, index: Index },
    IndexRenamed { store: u32, index: u32, old: String },
    Version(u64),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
    VersionChange,
}

struct Tx {
    mode: Mode,
    stores: Vec<String>,
    undo: Vec<Undo>,
}

pub struct Database {
    data: RwLock<DbData>,
    txs: Mutex<HashMap<u64, Tx>>,
}

impl Database {
    fn new() -> Self {
        Database { data: RwLock::new(DbData::default()), txs: Mutex::new(HashMap::new()) }
    }
}

type DbKey = (String, String);

#[derive(Default)]
struct Partition {
    dbs: Mutex<HashMap<DbKey, Arc<Database>>>,
}

static PARTITIONS: LazyLock<Mutex<HashMap<u64, Arc<Partition>>>> = LazyLock::new(Default::default);
static NAMES: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(Default::default);
static NEXT_PARTITION: AtomicU64 = AtomicU64::new(1);
static NEXT_TX: AtomicU64 = AtomicU64::new(1);
/// Live transaction -> its database, so per-op calls need no name lookup.
static TXS: LazyLock<Mutex<HashMap<u64, Arc<Database>>>> = LazyLock::new(Default::default);

/// The partition of a profile name (a CDP browser context, a session). One
/// per name for the life of the process, until [`drop_partition`].
pub fn partition_for(name: &str) -> u64 {
    let mut names = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(id) = names.get(name) {
        return *id;
    }
    let id = NEXT_PARTITION.fetch_add(1, Ordering::Relaxed);
    names.insert(name.to_string(), id);
    PARTITIONS.lock().unwrap_or_else(|e| e.into_inner()).insert(id, Arc::new(Partition::default()));
    id
}

/// Forget a profile's databases (its browser context was disposed).
pub fn drop_partition(name: &str) {
    let id = NAMES.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
    if let Some(id) = id {
        PARTITIONS.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }
}

/// The partition bound to a V8 context, set once when the engine built it:
/// a private property of its global, which no page can see or reach. Not a
/// context slot: rusty_v8 frees those with a weak handle whose callback could
/// run twice when the isolate was torn down ("Check failed:
/// node->IsInUse()").
fn storage_key<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Private> {
    let name = v8::String::new(scope, "nokk.storage").unwrap();
    v8::Private::for_api(scope, Some(name))
}

pub fn bind_context(scope: &mut v8::PinScope, partition: u64) {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = storage_key(scope);
    let id = v8::Number::new(scope, partition as f64);
    global.set_private(scope, key, id.into());
}

fn partition_of(scope: &mut v8::PinScope) -> Option<Arc<Partition>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = storage_key(scope);
    let v = global.get_private(scope, key)?;
    if !v.is_number() {
        return None;
    }
    let id = v.number_value(scope)? as u64;
    PARTITIONS.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned()
}

// ---- natives ---------------------------------------------------------------

/// Throw `[name, message]` into JS.
fn fail(scope: &mut v8::PinScope, name: &str, msg: &str) {
    let n = v8::String::new(scope, name).unwrap();
    let m = v8::String::new(scope, msg).unwrap();
    let arr = v8::Array::new_with_elements(scope, &[n.into(), m.into()]);
    scope.throw_exception(arr.into());
}

fn arg_str(scope: &mut v8::PinScope, args: &v8::FunctionCallbackArguments, i: i32) -> String {
    args.get(i).to_rust_string_lossy(scope)
}

fn tx_db(id: u64) -> Option<Arc<Database>> {
    TXS.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned()
}

fn db_handle(scope: &mut v8::PinScope, origin: &str, name: &str, create: bool) -> Option<Arc<Database>> {
    let part = partition_of(scope)?;
    let mut dbs = part.dbs.lock().unwrap_or_else(|e| e.into_inner());
    let key = (origin.to_string(), name.to_string());
    if let Some(db) = dbs.get(&key) {
        return Some(db.clone());
    }
    if !create {
        return None;
    }
    let db = Arc::new(Database::new());
    dbs.insert(key, db.clone());
    Some(db)
}

fn meta_value<'s>(scope: &mut v8::PinScope<'s, '_>, data: &DbData) -> v8::Local<'s, v8::Value> {
    let mut stores = Vec::new();
    for s in &data.stores {
        let mut idx = Vec::new();
        for ix in &s.indexes {
            let m = &ix.meta;
            let vals: [v8::Local<v8::Value>; 4] = [
                v8::String::new(scope, &m.name).unwrap().into(),
                m.key_path.to_value(scope),
                v8::Boolean::new(scope, m.unique).into(),
                v8::Boolean::new(scope, m.multi).into(),
            ];
            idx.push(v8::Array::new_with_elements(scope, &vals).into());
        }
        let idx_arr = v8::Array::new_with_elements(scope, &idx);
        let vals: [v8::Local<v8::Value>; 4] = [
            v8::String::new(scope, &s.name).unwrap().into(),
            s.key_path.to_value(scope),
            v8::Boolean::new(scope, s.auto_inc).into(),
            idx_arr.into(),
        ];
        stores.push(v8::Array::new_with_elements(scope, &vals).into());
    }
    let st = v8::Array::new_with_elements(scope, &stores);
    let ver = v8::Number::new(scope, data.version as f64);
    v8::Array::new_with_elements(scope, &[ver.into(), st.into()]).into()
}

/// `__pt_idbInfo(origin, name)`: `[version, stores]` or null.
fn info(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let origin = arg_str(scope, &args, 0);
    let name = arg_str(scope, &args, 1);
    let Some(db) = db_handle(scope, &origin, &name, false) else {
        rv.set_null();
        return;
    };
    let data = db.data.read().unwrap_or_else(|e| e.into_inner());
    let v = meta_value(scope, &data);
    rv.set(v);
}

/// `__pt_idbList(origin)`: `[[name, version], ...]`.
fn list(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let origin = arg_str(scope, &args, 0);
    let Some(part) = partition_of(scope) else {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    };
    let mut rows: Vec<(String, u64)> = Vec::new();
    for ((o, n), db) in part.dbs.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if *o == origin {
            let v = db.data.read().unwrap_or_else(|e| e.into_inner()).version;
            if v > 0 {
                rows.push((n.clone(), v));
            }
        }
    }
    rows.sort();
    let vals: Vec<v8::Local<v8::Value>> = rows
        .iter()
        .map(|(n, v)| {
            let a: [v8::Local<v8::Value>; 2] =
                [v8::String::new(scope, n).unwrap().into(), v8::Number::new(scope, *v as f64).into()];
            v8::Array::new_with_elements(scope, &a).into()
        })
        .collect();
    rv.set(v8::Array::new_with_elements(scope, &vals).into());
}

/// `__pt_idbDelete(origin, name)`: the old version, or null.
fn delete_db(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let origin = arg_str(scope, &args, 0);
    let name = arg_str(scope, &args, 1);
    let Some(part) = partition_of(scope) else {
        rv.set_null();
        return;
    };
    let removed = part.dbs.lock().unwrap_or_else(|e| e.into_inner()).remove(&(origin, name));
    match removed {
        Some(db) => {
            let v = db.data.read().unwrap_or_else(|e| e.into_inner()).version;
            rv.set(v8::Number::new(scope, v as f64).into());
        }
        None => rv.set_null(),
    }
}

/// `__pt_idbBegin(origin, name, stores[], mode)`: a transaction id, or 0
/// while an overlapping transaction holds the stores (the caller retries).
fn begin(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let origin = arg_str(scope, &args, 0);
    let name = arg_str(scope, &args, 1);
    let mode = match args.get(3).int32_value(scope).unwrap_or(0) {
        1 => Mode::ReadWrite,
        2 => Mode::VersionChange,
        _ => Mode::ReadOnly,
    };
    let mut stores = Vec::new();
    if let Ok(arr) = v8::Local::<v8::Array>::try_from(args.get(2)) {
        for i in 0..arr.length() {
            if let Some(v) = arr.get_index(scope, i) {
                stores.push(v.to_rust_string_lossy(scope));
            }
        }
    }
    let Some(db) = db_handle(scope, &origin, &name, mode == Mode::VersionChange) else {
        rv.set_int32(0);
        return;
    };
    let mut txs = db.txs.lock().unwrap_or_else(|e| e.into_inner());
    let conflict = txs.values().any(|t| {
        if t.mode == Mode::VersionChange || mode == Mode::VersionChange {
            return true;
        }
        if t.mode == Mode::ReadOnly && mode == Mode::ReadOnly {
            return false;
        }
        t.stores.iter().any(|s| stores.contains(s))
    });
    if conflict {
        rv.set_int32(0);
        return;
    }
    let id = NEXT_TX.fetch_add(1, Ordering::Relaxed);
    txs.insert(id, Tx { mode, stores, undo: Vec::new() });
    drop(txs);
    TXS.lock().unwrap_or_else(|e| e.into_inner()).insert(id, db);
    rv.set(v8::Number::new(scope, id as f64).into());
}

/// `__pt_idbEnd(tx, commit)`: commit keeps the changes, otherwise the undo
/// log is played back.
fn end(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, _rv: v8::ReturnValue) {
    let id = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    let commit = args.get(1).boolean_value(scope);
    let Some(db) = TXS.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) else { return };
    let tx = db.txs.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    let Some(tx) = tx else { return };
    if commit || tx.undo.is_empty() {
        return;
    }
    let mut data = db.data.write().unwrap_or_else(|e| e.into_inner());
    for u in tx.undo.into_iter().rev() {
        rollback(&mut data, u);
    }
}

fn store_by_id(data: &mut DbData, id: u32) -> Option<&mut Store> {
    data.stores.iter_mut().find(|s| s.id == id)
}

fn unindex(store: &mut Store, pkey: &[u8], rec: &Record) {
    for (iid, keys) in &rec.ikeys {
        if let Some(ix) = store.indexes.iter_mut().find(|i| i.meta.id == *iid) {
            for k in keys {
                let mut e = k.clone();
                e.extend_from_slice(pkey);
                ix.entries.remove(&e);
            }
        }
    }
}

fn reindex(store: &mut Store, pkey: &[u8], rec: &Record) {
    for (iid, keys) in &rec.ikeys {
        if let Some(ix) = store.indexes.iter_mut().find(|i| i.meta.id == *iid) {
            for k in keys {
                let mut e = k.clone();
                e.extend_from_slice(pkey);
                ix.entries.insert(e);
            }
        }
    }
}

fn rollback(data: &mut DbData, u: Undo) {
    match u {
        Undo::Record { store, key, old } => {
            let Some(s) = store_by_id(data, store) else { return };
            if let Some(cur) = s.records.remove(&key) {
                unindex(s, &key, &cur);
            }
            if let Some(old) = old {
                reindex(s, &key, &old);
                s.records.insert(key, old);
            }
        }
        Undo::KeyGen { store, old } => {
            if let Some(s) = store_by_id(data, store) {
                s.next = old;
            }
        }
        Undo::Cleared { store, records } => {
            let Some(s) = store_by_id(data, store) else { return };
            for ix in &mut s.indexes {
                ix.entries.clear();
            }
            s.records = records;
            let recs: Vec<(Vec<u8>, Record)> = s.records.iter().map(|(k, r)| (k.clone(), r.clone())).collect();
            for (k, r) in recs {
                reindex(s, &k, &r);
            }
        }
        Undo::StoreCreated(id) => data.stores.retain(|s| s.id != id),
        Undo::StoreDeleted(store) => data.stores.push(store),
        Undo::StoreRenamed { store, old } => {
            if let Some(s) = store_by_id(data, store) {
                s.name = old;
            }
        }
        Undo::IndexCreated { store, index } => {
            if let Some(s) = store_by_id(data, store) {
                s.indexes.retain(|i| i.meta.id != index);
                for r in s.records.values_mut() {
                    r.ikeys.retain(|(i, _)| *i != index);
                }
            }
        }
        Undo::IndexDeleted { store, index } => {
            if let Some(s) = store_by_id(data, store) {
                s.indexes.push(index);
            }
        }
        Undo::IndexRenamed { store, index, old } => {
            if let Some(s) = store_by_id(data, store) {
                if let Some(i) = s.indexes.iter_mut().find(|i| i.meta.id == index) {
                    i.meta.name = old;
                }
            }
        }
        Undo::Version(v) => data.version = v,
    }
}

/// Run `f` with the transaction's database locked for writing and its undo
/// log at hand.
fn with_write<R>(
    scope: &mut v8::PinScope,
    id: u64,
    f: impl FnOnce(&mut v8::PinScope, &mut DbData, &mut Vec<Undo>) -> R,
) -> Option<R> {
    let Some(db) = tx_db(id) else {
        fail(scope, "TransactionInactiveError", "The transaction has finished.");
        return None;
    };
    let mut data = db.data.write().unwrap_or_else(|e| e.into_inner());
    let mut txs = db.txs.lock().unwrap_or_else(|e| e.into_inner());
    let tx = txs.get_mut(&id)?;
    Some(f(scope, &mut data, &mut tx.undo))
}

/// `__pt_idbSchema(tx, op, ...)`: version-change operations.
/// op 0 version(v); 1 createStore(name, keyPath, autoInc); 2 deleteStore(name);
/// 3 renameStore(old, new); 4 createIndex(store, name, keyPath, unique, multi);
/// 5 deleteIndex(store, name); 6 renameIndex(store, old, new).
fn schema(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let id = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    let op = args.get(1).int32_value(scope).unwrap_or(-1);
    let a2 = args.get(2);
    let a3 = args.get(3);
    let a4 = args.get(4);
    let a5 = args.get(5);
    let a6 = args.get(6);
    let r = with_write(scope, id, |scope, data, undo| -> Result<(), (&'static str, String)> {
        match op {
            0 => {
                undo.push(Undo::Version(data.version));
                data.version = a2.number_value(scope).unwrap_or(0.0) as u64;
            }
            1 => {
                let name = a2.to_rust_string_lossy(scope);
                let key_path = KeyPath::from_value(scope, a3);
                let auto_inc = a4.boolean_value(scope);
                data.next_id += 1;
                let sid = data.next_id;
                data.stores.push(Store {
                    id: sid,
                    name,
                    key_path,
                    auto_inc,
                    next: 1.0,
                    records: BTreeMap::new(),
                    indexes: Vec::new(),
                });
                undo.push(Undo::StoreCreated(sid));
            }
            2 => {
                let name = a2.to_rust_string_lossy(scope);
                if let Some(pos) = data.stores.iter().position(|s| s.name == name) {
                    undo.push(Undo::StoreDeleted(data.stores.remove(pos)));
                }
            }
            3 => {
                let old = a2.to_rust_string_lossy(scope);
                let new = a3.to_rust_string_lossy(scope);
                if let Some(s) = data.store_mut(&old) {
                    undo.push(Undo::StoreRenamed { store: s.id, old: s.name.clone() });
                    s.name = new;
                }
            }
            4 => {
                let store = a2.to_rust_string_lossy(scope);
                let name = a3.to_rust_string_lossy(scope);
                let key_path = KeyPath::from_value(scope, a4);
                let unique = a5.boolean_value(scope);
                let multi = a6.boolean_value(scope);
                data.next_id += 1;
                let iid = data.next_id;
                let Some(s) = data.store_mut(&store) else { return Ok(()) };
                let meta = IndexMeta { id: iid, name, key_path, unique, multi };
                // Index the records already there; a unique index over
                // duplicates aborts the upgrade with ConstraintError.
                let mut entries = BTreeSet::new();
                let mut per_record: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
                let mut dup = false;
                let pairs: Vec<(Vec<u8>, Arc<Vec<u8>>)> =
                    s.records.iter().map(|(k, r)| (k.clone(), r.value.clone())).collect();
                for (pk, bytes) in pairs {
                    let v = deserialize(scope, &bytes);
                    let keys = index_keys(scope, v, &meta);
                    for k in &keys {
                        if unique {
                            let clash = entries.range::<Vec<u8>, _>((Bound::Included(k.clone()), Bound::Unbounded))
                                .next()
                                .is_some_and(|e: &Vec<u8>| e.starts_with(k));
                            if clash {
                                dup = true;
                            }
                        }
                        let mut e = k.clone();
                        e.extend_from_slice(&pk);
                        entries.insert(e);
                    }
                    per_record.push((pk, keys));
                }
                for (pk, keys) in per_record {
                    if let Some(r) = s.records.get_mut(&pk) {
                        r.ikeys.push((iid, keys));
                    }
                }
                s.indexes.push(Index { meta, entries });
                let sid = s.id;
                undo.push(Undo::IndexCreated { store: sid, index: iid });
                if dup {
                    return Err(("ConstraintError", "Index key is not unique.".to_string()));
                }
            }
            5 => {
                let store = a2.to_rust_string_lossy(scope);
                let name = a3.to_rust_string_lossy(scope);
                let Some(s) = data.store_mut(&store) else { return Ok(()) };
                if let Some(pos) = s.indexes.iter().position(|i| i.meta.name == name) {
                    let ix = s.indexes.remove(pos);
                    let sid = s.id;
                    undo.push(Undo::IndexDeleted { store: sid, index: ix });
                }
            }
            6 => {
                let store = a2.to_rust_string_lossy(scope);
                let old = a3.to_rust_string_lossy(scope);
                let new = a4.to_rust_string_lossy(scope);
                let Some(s) = data.store_mut(&store) else { return Ok(()) };
                let sid = s.id;
                if let Some(ix) = s.indexes.iter_mut().find(|i| i.meta.name == old) {
                    undo.push(Undo::IndexRenamed { store: sid, index: ix.meta.id, old: ix.meta.name.clone() });
                    ix.meta.name = new;
                }
            }
            _ => {}
        }
        Ok(())
    });
    if let Some(Err((name, msg))) = r {
        let n = v8::String::new(scope, name).unwrap();
        let m = v8::String::new(scope, &msg).unwrap();
        rv.set(v8::Array::new_with_elements(scope, &[n.into(), m.into()]).into());
    }
}

/// A value checked and cloned at `put()` time, written when the request is
/// processed. Kept in JS as an opaque external.
pub struct Prepared {
    key: Option<Key>,
    value: Vec<u8>,
    /// For a store with a key generator and an inline key path the key is
    /// injected into the value when it is written.
    inject: bool,
}

thread_local! {
    static PREPARED: std::cell::RefCell<HashMap<u64, Prepared>> = std::cell::RefCell::new(HashMap::new());
}
static NEXT_PREP: AtomicU64 = AtomicU64::new(1);

/// "Check that a key could be injected into a value".
fn can_inject<'s>(scope: &mut v8::PinScope<'s, '_>, value: v8::Local<'s, v8::Value>, path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = value;
    for ident in &parts[..parts.len() - 1] {
        if !cur.is_object() {
            return false;
        }
        let obj = cur.to_object(scope).unwrap();
        let name = v8::String::new(scope, ident).unwrap();
        if !obj.has_own_property(scope, name.into()).unwrap_or(false) {
            return true;
        }
        cur = obj.get(scope, name.into()).unwrap();
    }
    cur.is_object()
}

/// Inject `key` at the store's key path into the clone `value`.
fn inject_key<'s>(scope: &mut v8::PinScope<'s, '_>, value: v8::Local<'s, v8::Value>, path: &str, key: &Key) -> bool {
    let mut cur = value;
    let parts: Vec<&str> = path.split('.').collect();
    for (i, ident) in parts.iter().enumerate() {
        let Ok(obj) = v8::Local::<v8::Object>::try_from(cur) else { return false };
        let name = v8::String::new(scope, ident).unwrap();
        if i + 1 == parts.len() {
            let kv = key_to_value(scope, key);
            return obj.create_data_property(scope, name.into(), kv).unwrap_or(false);
        }
        if !obj.has_own_property(scope, name.into()).unwrap_or(false) {
            let o = v8::Object::new(scope);
            obj.create_data_property(scope, name.into(), o.into());
            cur = o.into();
        } else {
            cur = obj.get(scope, name.into()).unwrap();
        }
    }
    false
}

/// `__pt_idbPrepare(keyPath, autoIncrement, value, key, hasKey)`: the
/// synchronous half of `put`/`add`: clone, key checks, from the store's
/// definition as the connection knows it (no lock, and a transaction still
/// waiting for its stores can take requests). Returns a ticket, or throws
/// `[name, message]` (DataError, DataCloneError) without the prefix.
fn prepare(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let key_path = KeyPath::from_value(scope, args.get(0));
    let auto_inc = args.get(1).boolean_value(scope);
    let value = args.get(2);
    let key_arg = args.get(3);
    let has_key = args.get(4).boolean_value(scope);
    let inline = key_path != KeyPath::None;
    if inline && has_key {
        fail(scope, "DataError", "The object store uses in-line keys and the key parameter was provided.");
        return;
    }
    if !inline && !auto_inc && !has_key {
        fail(scope, "DataError", "The object store uses out-of-line keys and has no key generator and the key parameter was not provided.");
        return;
    }
    let mut key = None;
    if has_key {
        match to_key(scope, key_arg) {
            Some(k) => key = Some(k),
            None => {
                fail(scope, "DataError", "The parameter is not a valid key.");
                return;
            }
        }
    }
    let bytes = match serialize(scope, value) {
        Ok(b) => b,
        Err(msg) => {
            fail(scope, "DataCloneError", &msg);
            return;
        }
    };
    let mut inject = false;
    if inline {
        let clone = deserialize(scope, &bytes);
        match key_at_path(scope, clone, &key_path) {
            Ok(Some(k)) => key = Some(k),
            Ok(None) if auto_inc => {
                // The generator will supply the key; it must fit in the value.
                let can = match &key_path {
                    KeyPath::Str(p) => can_inject(scope, clone, p),
                    _ => false,
                };
                if !can {
                    fail(scope, "DataError", "A generated key could not be inserted into the value.");
                    return;
                }
                inject = true;
            }
            Ok(None) => {
                fail(scope, "DataError", "Evaluating the object store's key path did not yield a value.");
                return;
            }
            Err(()) => {
                fail(scope, "DataError", "Evaluating the object store's key path yielded a value that is not a valid key.");
                return;
            }
        }
    }
    let ticket = NEXT_PREP.fetch_add(1, Ordering::Relaxed);
    PREPARED.with(|p| p.borrow_mut().insert(ticket, Prepared { key, value: bytes, inject }));
    rv.set(v8::Number::new(scope, ticket as f64).into());
}

/// `__pt_idbDrop(ticket)`: a prepared value whose request never ran.
fn drop_prepared(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, _rv: v8::ReturnValue) {
    let t = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    PREPARED.with(|p| p.borrow_mut().remove(&t));
}

/// `__pt_idbStore(tx, store, ticket, noOverwrite)`: write a prepared value;
/// returns the key. ConstraintError is returned as `[name, message]`.
fn store_put(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let id = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    let store_name = arg_str(scope, &args, 1);
    let ticket = args.get(2).number_value(scope).unwrap_or(0.0) as u64;
    let no_overwrite = args.get(3).boolean_value(scope);
    let Some(prep) = PREPARED.with(|p| p.borrow_mut().remove(&ticket)) else {
        rv.set_undefined();
        return;
    };
    let r = with_write(scope, id, |scope, data, undo| -> Result<Key, (&'static str, String)> {
        let Some(s) = data.store_mut(&store_name) else {
            return Err(("InvalidStateError", "The object store has been deleted.".into()));
        };
        let mut value = prep.value;
        let key = match prep.key {
            Some(k) => {
                // A key above the generator moves it on.
                if s.auto_inc {
                    if let Key::Num(n) = k {
                        if n >= s.next {
                            undo.push(Undo::KeyGen { store: s.id, old: s.next });
                            s.next = (n.floor() + 1.0).min(9007199254740992.0 + 1.0);
                        }
                    }
                }
                k
            }
            None => {
                if s.next > 9007199254740992.0 {
                    return Err(("ConstraintError", "Key generator has reached its maximum value.".into()));
                }
                let k = Key::Num(s.next);
                undo.push(Undo::KeyGen { store: s.id, old: s.next });
                s.next += 1.0;
                k
            }
        };
        let clone = deserialize(scope, &value);
        if prep.inject {
            if let KeyPath::Str(p) = &s.key_path {
                inject_key(scope, clone, p, &key);
                if let Ok(b) = serialize(scope, clone) {
                    value = b;
                }
            }
        }
        let pkey = key.encode();
        if no_overwrite && s.records.contains_key(&pkey) {
            return Err(("ConstraintError", "Key already exists in the object store.".into()));
        }
        // Index keys, and the uniqueness check before anything changes.
        let metas: Vec<IndexMeta> = s.indexes.iter().map(|i| i.meta.clone()).collect();
        let mut ikeys = Vec::with_capacity(metas.len());
        for m in &metas {
            let keys = index_keys(scope, clone, m);
            if m.unique {
                let ix = s.indexes.iter().find(|i| i.meta.id == m.id).unwrap();
                for k in &keys {
                    let clash = ix
                        .entries
                        .range::<Vec<u8>, _>((Bound::Included(k.clone()), Bound::Unbounded))
                        .take_while(|e| e.starts_with(k))
                        .any(|e| e[k.len()..] != pkey[..]);
                    if clash {
                        return Err((
                            "ConstraintError",
                            format!("Unable to add key to index '{}': at least one key does not satisfy the uniqueness requirements.", m.name),
                        ));
                    }
                }
            }
            ikeys.push((m.id, keys));
        }
        let rec = Record { value: Arc::new(value), ikeys };
        let old = s.records.remove(&pkey);
        if let Some(o) = &old {
            unindex(s, &pkey, o);
        }
        reindex(s, &pkey, &rec);
        s.records.insert(pkey.clone(), rec);
        undo.push(Undo::Record { store: s.id, key: pkey, old });
        Ok(key)
    });
    match r {
        Some(Ok(k)) => {
            let v = key_to_value(scope, &k);
            rv.set(v);
        }
        Some(Err((name, msg))) => {
            let n = v8::String::new(scope, name).unwrap();
            let m = v8::String::new(scope, &msg).unwrap();
            let arr = v8::Array::new_with_elements(scope, &[n.into(), m.into()]);
            let o = v8::Object::new(scope);
            let k = v8::String::new(scope, "e").unwrap();
            o.set(scope, k.into(), arr.into());
            rv.set(o.into());
        }
        None => {}
    }
}

/// A key range from JS: `undefined`/`null` (everything), or
/// `[lower, upper, lowerOpen, upperOpen]` with `undefined` for an open end.
/// A record found by a read: (index key, primary key, value), encoded.
type Row = (Vec<u8>, Vec<u8>, Option<Arc<Vec<u8>>>);

struct Range {
    lower: Bound<Vec<u8>>,
    upper: Bound<Vec<u8>>,
}

fn range_arg(scope: &mut v8::PinScope, v: v8::Local<v8::Value>) -> Option<Range> {
    if v.is_null_or_undefined() {
        return Some(Range { lower: Bound::Unbounded, upper: Bound::Unbounded });
    }
    let arr = v8::Local::<v8::Array>::try_from(v).ok()?;
    let lo = arr.get_index(scope, 0)?;
    let hi = arr.get_index(scope, 1)?;
    let lo_open = arr.get_index(scope, 2)?.boolean_value(scope);
    let hi_open = arr.get_index(scope, 3)?.boolean_value(scope);
    let bound = |scope: &mut v8::PinScope, v: v8::Local<v8::Value>, open: bool| -> Option<Bound<Vec<u8>>> {
        if v.is_undefined() {
            return Some(Bound::Unbounded);
        }
        let k = to_key(scope, v)?.encode();
        Some(if open { Bound::Excluded(k) } else { Bound::Included(k) })
    };
    Some(Range { lower: bound(scope, lo, lo_open)?, upper: bound(scope, hi, hi_open)? })
}

/// For an index range: entries are key ++ primary, so an included upper
/// bound must take every primary key after it.
fn index_bounds(r: &Range) -> (Bound<Vec<u8>>, Bound<Vec<u8>>) {
    let lower = match &r.lower {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(b) => Bound::Included(b.clone()),
        Bound::Excluded(b) => {
            let mut e = b.clone();
            e.push(0xFF);
            Bound::Excluded(e)
        }
    };
    let upper = match &r.upper {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(b) => {
            let mut e = b.clone();
            e.push(0xFF);
            Bound::Excluded(e)
        }
        Bound::Excluded(b) => Bound::Excluded(b.clone()),
    };
    (lower, upper)
}

fn split_entry(e: &[u8]) -> (&[u8], &[u8]) {
    let n = Key::encoded_len(e).unwrap_or(e.len());
    (&e[..n], &e[n..])
}

fn decode_value<'s>(scope: &mut v8::PinScope<'s, '_>, enc: &[u8]) -> v8::Local<'s, v8::Value> {
    match Key::decode(enc) {
        Some(k) => key_to_value(scope, &k),
        None => v8::undefined(scope).into(),
    }
}

/// `__pt_idbRead(tx, store, index, range, kind, count, reverse)`:
/// kind 0 get (value), 1 getKey (primary key), 2 getAll (values),
/// 3 getAllKeys (primary keys), 4 count, 5 getAllRecords ([key, primary, value]).
fn read(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let id = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    let store_name = arg_str(scope, &args, 1);
    let index = args.get(2);
    let index_name = if index.is_null_or_undefined() { None } else { Some(index.to_rust_string_lossy(scope)) };
    let range_v = args.get(3);
    let kind = args.get(4).int32_value(scope).unwrap_or(0);
    let limit = {
        let c = args.get(5);
        if c.is_null_or_undefined() { 0 } else { c.uint32_value(scope).unwrap_or(0) as usize }
    };
    let limit = if limit == 0 { usize::MAX } else { limit };
    let reverse = args.get(6).boolean_value(scope);
    let Some(db) = tx_db(id) else {
        fail(scope, "TransactionInactiveError", "The transaction has finished.");
        return;
    };
    let Some(range) = range_arg(scope, range_v) else {
        fail(scope, "DataError", "The parameter is not a valid key.");
        return;
    };
    let data = db.data.read().unwrap_or_else(|e| e.into_inner());
    let Some(s) = data.store(&store_name) else {
        fail(scope, "InvalidStateError", "The object store has been deleted.");
        return;
    };
    let single = kind == 0 || kind == 1;
    let want = if single { 1 } else { limit };
    // (index key, primary key, record) in order, at most `want`.
    let mut hits: Vec<Row> = Vec::new();
    let need_value = kind == 0 || kind == 2 || kind == 5;
    match &index_name {
        None => {
            let it = s.records.range::<Vec<u8>, _>((range.lower.clone(), range.upper.clone()));
            if kind == 4 {
                rv.set(v8::Number::new(scope, it.count() as f64).into());
                return;
            }
            let push = |hits: &mut Vec<_>, (k, r): (&Vec<u8>, &Record)| {
                hits.push((k.clone(), k.clone(), if need_value { Some(r.value.clone()) } else { None }));
            };
            if reverse {
                for e in it.rev().take(want) {
                    push(&mut hits, e);
                }
            } else {
                for e in it.take(want) {
                    push(&mut hits, e);
                }
            }
        }
        Some(iname) => {
            let Some(ix) = s.indexes.iter().find(|i| &i.meta.name == iname) else {
                fail(scope, "InvalidStateError", "The index has been deleted.");
                return;
            };
            let (lo, hi) = index_bounds(&range);
            let it = ix.entries.range::<Vec<u8>, _>((lo, hi));
            if kind == 4 {
                rv.set(v8::Number::new(scope, it.count() as f64).into());
                return;
            }
            let mut push = |e: &Vec<u8>| {
                let (ik, pk) = split_entry(e);
                let val = if need_value { s.records.get(pk).map(|r| r.value.clone()) } else { None };
                hits.push((ik.to_vec(), pk.to_vec(), val));
            };
            if reverse {
                for e in it.rev().take(want) {
                    push(e);
                }
            } else {
                for e in it.take(want) {
                    push(e);
                }
            }
        }
    }
    drop(data);
    if single {
        match hits.first() {
            None => rv.set_undefined(),
            Some((_, pk, val)) => {
                let v = if kind == 0 { deserialize(scope, val.as_ref().unwrap()) } else { decode_value(scope, pk) };
                rv.set(v);
            }
        }
        return;
    }
    let mut out = Vec::with_capacity(hits.len());
    for (ik, pk, val) in &hits {
        let v = match kind {
            2 => deserialize(scope, val.as_ref().unwrap()),
            3 => decode_value(scope, pk),
            _ => {
                let a: [v8::Local<v8::Value>; 3] = [
                    decode_value(scope, ik),
                    decode_value(scope, pk),
                    val.as_ref().map(|b| deserialize(scope, b)).unwrap_or_else(|| v8::undefined(scope).into()),
                ];
                v8::Array::new_with_elements(scope, &a).into()
            }
        };
        out.push(v);
    }
    rv.set(v8::Array::new_with_elements(scope, &out).into());
}

/// `__pt_idbDelete(tx, store, range)` and `clear` (range null, `clear` true).
fn delete_records(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, _rv: v8::ReturnValue) {
    let id = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    let store_name = arg_str(scope, &args, 1);
    let range_v = args.get(2);
    let clear = args.get(3).boolean_value(scope);
    let Some(range) = range_arg(scope, range_v) else {
        fail(scope, "DataError", "The parameter is not a valid key.");
        return;
    };
    with_write(scope, id, |_scope, data, undo| {
        let Some(s) = data.store_mut(&store_name) else { return };
        if clear {
            let records = std::mem::take(&mut s.records);
            for ix in &mut s.indexes {
                ix.entries.clear();
            }
            undo.push(Undo::Cleared { store: s.id, records });
            return;
        }
        let keys: Vec<Vec<u8>> =
            s.records.range::<Vec<u8>, _>((range.lower.clone(), range.upper.clone())).map(|(k, _)| k.clone()).collect();
        for k in keys {
            if let Some(old) = s.records.remove(&k) {
                unindex(s, &k, &old);
                undo.push(Undo::Record { store: s.id, key: k, old: Some(old) });
            }
        }
    });
}

/// The next position of a cursor after (`pos`) or at (`target`) a point:
/// (key, primary key), encoded. `dir` 0 next, 1 nextunique, 2 prev, 3 prevunique.
#[allow(clippy::too_many_arguments)]
fn cursor_next(
    s: &Store,
    index: Option<&Index>,
    range: &Range,
    dir: i32,
    pos_key: Option<&[u8]>,
    pos_primary: Option<&[u8]>,
    target_key: Option<&[u8]>,
    target_primary: Option<&[u8]>,
    mut skip: u32,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let rev = dir >= 2;
    let unique = dir == 1 || dir == 3;
    let Some(ix) = index else {
        // Store cursor: key == primary key.
        let mut lower = range.lower.clone();
        let mut upper = range.upper.clone();
        if !rev {
            if let Some(p) = pos_key {
                lower = tighter_lower(lower, Bound::Excluded(p.to_vec()));
            }
            if let Some(t) = target_key {
                lower = tighter_lower(lower, Bound::Included(t.to_vec()));
            }
        } else {
            if let Some(p) = pos_key {
                upper = tighter_upper(upper, Bound::Excluded(p.to_vec()));
            }
            if let Some(t) = target_key {
                upper = tighter_upper(upper, Bound::Included(t.to_vec()));
            }
        }
        if bounds_empty(&lower, &upper) {
            return None;
        }
        let r = s.records.range::<Vec<u8>, _>((lower, upper));
        let k = if rev { r.rev().nth(skip as usize) } else { r.into_iter().nth(skip as usize) };
        return k.map(|(k, _)| (k.clone(), k.clone()));
    };
    let (mut lo, mut hi) = index_bounds(range);
    let pos_entry = match (pos_key, pos_primary) {
        (Some(k), Some(p)) => {
            let mut e = k.to_vec();
            e.extend_from_slice(p);
            Some(e)
        }
        _ => None,
    };
    if !rev {
        if let Some(e) = &pos_entry {
            if unique {
                let mut after = pos_key.unwrap().to_vec();
                after.push(0xFF);
                lo = tighter_lower(lo, Bound::Excluded(after));
            } else {
                lo = tighter_lower(lo, Bound::Excluded(e.clone()));
            }
        }
        if let Some(t) = target_key {
            let mut e = t.to_vec();
            if let Some(tp) = target_primary {
                e.extend_from_slice(tp);
            }
            lo = tighter_lower(lo, Bound::Included(e));
        }
    } else {
        if let Some(e) = &pos_entry {
            if unique {
                hi = tighter_upper(hi, Bound::Excluded(pos_key.unwrap().to_vec()));
            } else {
                hi = tighter_upper(hi, Bound::Excluded(e.clone()));
            }
        }
        if let Some(t) = target_key {
            let mut e = t.to_vec();
            match target_primary {
                Some(tp) => {
                    e.extend_from_slice(tp);
                    hi = tighter_upper(hi, Bound::Included(e));
                }
                None => {
                    e.push(0xFF);
                    hi = tighter_upper(hi, Bound::Excluded(e));
                }
            }
        }
    }
    if bounds_empty(&lo, &hi) {
        return None;
    }
    let it: Box<dyn Iterator<Item = &Vec<u8>>> = if rev {
        Box::new(ix.entries.range::<Vec<u8>, _>((lo, hi)).rev())
    } else {
        Box::new(ix.entries.range::<Vec<u8>, _>((lo, hi)))
    };
    let mut last_key: Option<&[u8]> = None;
    for e in it {
        let (k, p) = split_entry(e);
        if unique && last_key == Some(k) {
            continue;
        }
        last_key = Some(k);
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if unique && rev {
            // prevunique lands on the lowest primary key of its key.
            let first = ix
                .entries
                .range::<Vec<u8>, _>((Bound::Included(k.to_vec()), Bound::Unbounded))
                .next()
                .map(|e| split_entry(e).1.to_vec())
                .unwrap_or_else(|| p.to_vec());
            return Some((k.to_vec(), first));
        }
        return Some((k.to_vec(), p.to_vec()));
    }
    None
}

fn one_byte_arg(scope: &mut v8::PinScope, v: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    let s = v8::Local::<v8::String>::try_from(v).ok()?;
    let mut out = vec![0u8; s.length()];
    s.write_one_byte_v2(scope, 0, &mut out, v8::WriteFlags::empty());
    Some(out)
}

fn one_byte_value<'s>(scope: &mut v8::PinScope<'s, '_>, b: &[u8]) -> v8::Local<'s, v8::Value> {
    v8::String::new_from_one_byte(scope, b, v8::NewStringType::Normal)
        .map(Into::into)
        .unwrap_or_else(|| v8::undefined(scope).into())
}

/// `__pt_idbCursor(tx, store, index, range, dir, posKey, posPrimary,
/// targetKey, targetPrimary, skip, withValue, count)`: up to `count`
/// records from the cursor's position on, as Chrome prefetches. Positions
/// are encoded keys in one-byte strings handed back by an earlier call.
/// Returns a flat array `[key, primaryKey, value, posKey, posPrimary, ...]`.
fn cursor(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let id = args.get(0).number_value(scope).unwrap_or(0.0) as u64;
    let store_name = arg_str(scope, &args, 1);
    let index = args.get(2);
    let index_name = if index.is_null_or_undefined() { None } else { Some(index.to_rust_string_lossy(scope)) };
    let Some(range) = range_arg(scope, args.get(3)) else {
        fail(scope, "DataError", "The parameter is not a valid key.");
        return;
    };
    let dir = args.get(4).int32_value(scope).unwrap_or(0);
    let mut pos_key = one_byte_arg(scope, args.get(5));
    let mut pos_primary = one_byte_arg(scope, args.get(6));
    let target_key = {
        let v = args.get(7);
        if v.is_undefined() { None } else { to_key(scope, v).map(|k| k.encode()) }
    };
    let target_primary = {
        let v = args.get(8);
        if v.is_undefined() { None } else { to_key(scope, v).map(|k| k.encode()) }
    };
    let skip = args.get(9).uint32_value(scope).unwrap_or(0);
    let with_value = args.get(10).boolean_value(scope);
    let count = args.get(11).uint32_value(scope).unwrap_or(1).clamp(1, 1024) as usize;
    let Some(db) = tx_db(id) else {
        fail(scope, "TransactionInactiveError", "The transaction has finished.");
        return;
    };
    // Collect under the lock, convert to JS after it.
    let mut rows: Vec<Row> = Vec::new();
    {
        let data = db.data.read().unwrap_or_else(|e| e.into_inner());
        let Some(s) = data.store(&store_name) else {
            rv.set_null();
            return;
        };
        let ix = match &index_name {
            None => None,
            Some(n) => match s.indexes.iter().find(|i| &i.meta.name == n) {
                Some(i) => Some(i),
                None => {
                    rv.set_null();
                    return;
                }
            },
        };
        let mut first = true;
        while rows.len() < count {
            let found = cursor_next(
                s,
                ix,
                &range,
                dir,
                pos_key.as_deref(),
                pos_primary.as_deref(),
                if first { target_key.as_deref() } else { None },
                if first { target_primary.as_deref() } else { None },
                if first { skip } else { 0 },
            );
            first = false;
            let Some((k, p)) = found else { break };
            let value = if with_value { s.records.get(&p).map(|r| r.value.clone()) } else { None };
            pos_key = Some(k.clone());
            pos_primary = Some(p.clone());
            rows.push((k, p, value));
        }
    }
    let mut out: Vec<v8::Local<v8::Value>> = Vec::with_capacity(rows.len() * 5);
    for (k, p, value) in &rows {
        out.push(decode_value(scope, k));
        out.push(decode_value(scope, p));
        out.push(match value {
            Some(b) => deserialize(scope, b),
            None => v8::undefined(scope).into(),
        });
        out.push(one_byte_value(scope, k));
        out.push(one_byte_value(scope, p));
    }
    rv.set(v8::Array::new_with_elements(scope, &out).into());
}

fn tighter_lower(a: Bound<Vec<u8>>, b: Bound<Vec<u8>>) -> Bound<Vec<u8>> {
    match (&a, &b) {
        (Bound::Unbounded, _) => b,
        (_, Bound::Unbounded) => a,
        (Bound::Included(x) | Bound::Excluded(x), Bound::Included(y) | Bound::Excluded(y)) => {
            if y > x || (y == x && matches!(b, Bound::Excluded(_))) { b } else { a }
        }
    }
}

fn tighter_upper(a: Bound<Vec<u8>>, b: Bound<Vec<u8>>) -> Bound<Vec<u8>> {
    match (&a, &b) {
        (Bound::Unbounded, _) => b,
        (_, Bound::Unbounded) => a,
        (Bound::Included(x) | Bound::Excluded(x), Bound::Included(y) | Bound::Excluded(y)) => {
            if y < x || (y == x && matches!(b, Bound::Excluded(_))) { b } else { a }
        }
    }
}

/// `BTreeMap::range` panics on an inverted range; such a range is empty.
fn bounds_empty(lo: &Bound<Vec<u8>>, hi: &Bound<Vec<u8>>) -> bool {
    match (lo, hi) {
        (Bound::Included(a), Bound::Included(b)) => a > b,
        (Bound::Included(a), Bound::Excluded(b)) | (Bound::Excluded(a), Bound::Included(b)) => a >= b,
        (Bound::Excluded(a), Bound::Excluded(b)) => a >= b,
        _ => false,
    }
}

/// `__pt_idbCmp(a, b)`: -1, 0 or 1; throws DataError for a non-key.
fn cmp(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let a = to_key(scope, args.get(0));
    let b = to_key(scope, args.get(1));
    match (a, b) {
        (Some(a), Some(b)) => {
            let o = a.encode().cmp(&b.encode());
            rv.set_int32(o as i32);
        }
        _ => fail(scope, "DataError", "The parameter is not a valid key."),
    }
}

/// `__pt_idbKey(v)`: the key as a fresh value (dates, arrays and buffers
/// copied, buffers as ArrayBuffer), or throws DataError.
fn key_copy(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    match to_key(scope, args.get(0)) {
        Some(k) => {
            let v = key_to_value(scope, &k);
            rv.set(v);
        }
        None => fail(scope, "DataError", "The parameter is not a valid key."),
    }
}

/// `__pt_idbClone(v)`: structured clone through V8's serializer (DataCloneError
/// as `[name, message]`).
fn clone_value(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    match serialize(scope, args.get(0)) {
        Ok(b) => {
            let v = deserialize(scope, &b);
            rv.set(v);
        }
        Err(msg) => fail(scope, "DataCloneError", &msg),
    }
}

/// `__pt_idbKeyOf(store meta keyPath, value)`: the key a key path yields
/// from a value, for cursor.update checks. undefined when none, throws
/// DataError when not a key.
fn key_of(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let path = KeyPath::from_value(scope, args.get(0));
    let value = v8::Local::new(scope, args.get(1));
    match key_at_path(scope, value, &path) {
        Ok(Some(k)) => {
            let v = key_to_value(scope, &k);
            rv.set(v);
        }
        Ok(None) => rv.set_undefined(),
        Err(()) => fail(scope, "DataError", "The parameter is not a valid key."),
    }
}

/// `__pt_idbStats()`: `[live transactions, prepared values]` of the
/// process and this thread, for leak checks.
fn stats(scope: &mut v8::PinScope, _args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let txs = TXS.lock().unwrap_or_else(|e| e.into_inner()).len() as f64;
    let prepared = PREPARED.with(|p| p.borrow().len()) as f64;
    let a = v8::Number::new(scope, txs);
    let b = v8::Number::new(scope, prepared);
    rv.set(v8::Array::new_with_elements(scope, &[a.into(), b.into()]).into());
}

pub(crate) fn install(scope: &mut v8::PinScope) {
    use crate::natives::bind;
    bind(scope, "__pt_idbInfo", info);
    bind(scope, "__pt_idbList", list);
    bind(scope, "__pt_idbDeleteDb", delete_db);
    bind(scope, "__pt_idbBegin", begin);
    bind(scope, "__pt_idbEnd", end);
    bind(scope, "__pt_idbSchema", schema);
    bind(scope, "__pt_idbPrepare", prepare);
    bind(scope, "__pt_idbDrop", drop_prepared);
    bind(scope, "__pt_idbStore", store_put);
    bind(scope, "__pt_idbRead", read);
    bind(scope, "__pt_idbRemove", delete_records);
    bind(scope, "__pt_idbCursor", cursor);
    bind(scope, "__pt_idbCmp", cmp);
    bind(scope, "__pt_idbKey", key_copy);
    bind(scope, "__pt_idbClone", clone_value);
    bind(scope, "__pt_idbKeyOf", key_of);
    bind(scope, "__pt_idbStats", stats);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Key {
        Key::Str(x.encode_utf16().collect())
    }

    #[test]
    fn encoding_orders_keys_as_indexeddb() {
        let ordered = vec![
            Key::Num(f64::NEG_INFINITY),
            Key::Num(-1.5),
            Key::Num(0.0),
            Key::Num(0.5),
            Key::Num(9.0),
            Key::Num(10.0),
            Key::Num(f64::INFINITY),
            Key::Date(1.0),
            Key::Date(5.0),
            s(""),
            s("B"),
            s("a"),
            s("a\u{0}"),
            s("ab"),
            Key::Bin(vec![1]),
            Key::Bin(vec![1, 2]),
            Key::Arr(vec![]),
            Key::Arr(vec![Key::Num(1.0)]),
            Key::Arr(vec![Key::Num(1.0), Key::Num(2.0)]),
            Key::Arr(vec![Key::Num(1.0), s("a")]),
        ];
        for w in ordered.windows(2) {
            assert!(w[0].encode() < w[1].encode(), "{:?} < {:?}", w[0], w[1]);
        }
        assert_eq!(Key::Num(-0.0).encode(), Key::Num(0.0).encode());
        for k in &ordered {
            assert_eq!(Key::decode(&k.encode()).as_ref(), Some(k));
        }
    }

    #[test]
    fn an_index_entry_splits_into_key_and_primary_key() {
        let mut e = Key::Arr(vec![s("x\u{0}"), Key::Num(3.0)]).encode();
        let pk = Key::Bin(vec![0, 0, 1]).encode();
        e.extend_from_slice(&pk);
        let (k, p) = split_entry(&e);
        assert_eq!(Key::decode(k), Some(Key::Arr(vec![s("x\u{0}"), Key::Num(3.0)])));
        assert_eq!(p, &pk[..]);
    }
}
