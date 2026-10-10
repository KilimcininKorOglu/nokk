(() => {
  'use strict';
  // IndexedDB as Chrome 151 has it. The data lives in Rust (`__pt_idb*`,
  // crates/pool/src/idb.rs), shared by every page, frame and worker of the
  // profile; this layer is the page-facing objects and the transaction life
  // cycle. One engine task per request: the transaction is active while its
  // request's event is dispatched and through the microtasks after it, and
  // goes inactive in the next task, which also processes the next request or
  // commits. State lives in a WeakMap: the objects have no own properties.
  const G = globalThis;
  if (typeof G.__pt_idbBegin !== 'function' || typeof G.EventTarget !== 'function' || typeof G.__pt_addTask !== 'function') return;
  const I = {
    info: G.__pt_idbInfo, list: G.__pt_idbList, deleteDb: G.__pt_idbDeleteDb, begin: G.__pt_idbBegin,
    end: G.__pt_idbEnd, schema: G.__pt_idbSchema, prepare: G.__pt_idbPrepare, drop: G.__pt_idbDrop,
    put: G.__pt_idbStore, read: G.__pt_idbRead, remove: G.__pt_idbRemove, cursor: G.__pt_idbCursor,
    cmp: G.__pt_idbCmp, key: G.__pt_idbKey, clone: G.__pt_idbClone, keyOf: G.__pt_idbKeyOf,
  };
  const ET = G.EventTarget, Ev = G.Event, DOMEx = G.DOMException || Error;
  const ETdispatch = ET.prototype.dispatchEvent;
  const RA = Reflect.apply, isArray = Array.isArray, defineProperty = Object.defineProperty;
  const trust = G.__pt_trustEvent, task = G.__pt_addTask, mkErr = G.__pt_mkErr;
  const anyDue = typeof G.__pt_anyDue === 'function' ? G.__pt_anyDue : () => true;
  const reported = typeof G.__pt_reportedErrors === 'function' ? G.__pt_reportedErrors : () => 0;
  const parents = G.__pt_eventParents || new WeakMap();
  const PromiseC = Promise;
  const T = Symbol();
  const ST = new WeakMap();

  const state = (o, kind) => {
    const s = o !== null && typeof o === 'object' ? ST.get(o) : undefined;
    if (!s || (kind && s.kind !== kind)) throw mkErr(TypeError, 'Illegal invocation');
    return s;
  };
  const dom = (name, msg) => mkErr(DOMEx, msg, name);
  const failed = (iface, method, name, msg) => dom(name, "Failed to execute '" + method + "' on '" + iface + "': " + msg);
  const typeErr = (iface, method, msg) => mkErr(TypeError, "Failed to execute '" + method + "' on '" + iface + "': " + msg);
  const needArgs = (iface, method, n, got) => {
    if (got < n) throw typeErr(iface, method, n + (n === 1 ? ' argument' : ' arguments') + ' required, but only ' + got + ' present.');
  };
  // Native calls throw `[name, message]`; the page sees Chrome's wording.
  const call = (iface, method, f, a, b, c, d, e, g, h, i, j, k) => {
    try { return f(a, b, c, d, e, g, h, i, j, k); } catch (x) {
      if (isArray(x)) throw failed(iface, method, x[0], x[1]);
      throw x;
    }
  };
  const enumValue = (iface, method, v, allowed, type) => {
    const s = String(v);
    if (allowed.indexOf(s) < 0) throw typeErr(iface, method, "The provided value '" + s + "' is not a valid enum value of type " + type + '.');
    return s;
  };
  const ulong = (iface, method, v, what) => {
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0 || n > 4294967295) throw typeErr(iface, method, (what || 'Value') + " is outside the 'unsigned long' value range.");
    return Math.trunc(n);
  };

  // The document's origin, read once when first needed (a worker's is known
  // only after its scope is set up). An opaque origin has no storage.
  let originCache;
  const originOf = () => {
    if (originCache === undefined) {
      try { originCache = String(G.location.origin); } catch (e) { originCache = 'null'; }
    }
    return originCache;
  };
  const checkOrigin = (method) => {
    const o = originOf();
    if (o === 'null' || o === '' || o === 'undefined') throw failed('IDBFactory', method, 'SecurityError', 'access to the Indexed Database API is denied in this context.');
    return o;
  };

  // Valid key path: '' or identifiers joined by dots, or a non-empty array of those.
  const IDENT = /^[$_\p{ID_Start}][$_‌‍\p{ID_Continue}]*$/u;
  const validPathString = (p) => p === '' || p.split('.').every((x) => IDENT.test(x));
  const normPath = (p) => {
    if (p === null || p === undefined) return null;
    if (isArray(p)) {
      const out = p.map(String);
      if (!out.length || !out.every(validPathString)) return undefined;
      return out;
    }
    const s = String(p);
    return validPathString(s) ? s : undefined;
  };

  const fire = (target, type, bubbles, cancelable) => {
    const ev = new Ev(type, { bubbles, cancelable });
    if (trust) trust(ev);
    return RA(ETdispatch, target, [ev]);
  };

  // ---- DOMStringList -----------------------------------------------------
  class DOMStringList {
    constructor(tok, names) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      const self = Object.create(new.target.prototype);
      ST.set(self, { kind: 'list', names });
      for (let i = 0; i < names.length; i++) defineProperty(self, i, { value: names[i], enumerable: true, writable: false, configurable: false });
      return self;
    }
    get length() { return state(this, 'list').names.length; }
    contains(string) { needArgs('DOMStringList', 'contains', 1, arguments.length); return state(this, 'list').names.indexOf(String(string)) >= 0; }
    item(index) {
      needArgs('DOMStringList', 'item', 1, arguments.length);
      const n = state(this, 'list').names; const i = Number(index) >>> 0;
      return i < n.length ? n[i] : null;
    }
  }
  defineProperty(DOMStringList.prototype, Symbol.iterator, { value: Array.prototype.values, writable: true, configurable: true });
  const stringList = (names) => new DOMStringList(T, names.slice().sort());

  // ---- IDBKeyRange -------------------------------------------------------
  class IDBKeyRange {
    constructor(tok, lower, upper, lowerOpen, upperOpen) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      const self = Object.create(new.target.prototype);
      ST.set(self, { kind: 'range', lower, upper, lowerOpen, upperOpen });
      return self;
    }
    get lower() { return state(this, 'range').lower; }
    get upper() { return state(this, 'range').upper; }
    get lowerOpen() { return state(this, 'range').lowerOpen; }
    get upperOpen() { return state(this, 'range').upperOpen; }
    includes(key) {
      const r = state(this, 'range');
      needArgs('IDBKeyRange', 'includes', 1, arguments.length);
      const k = call('IDBKeyRange', 'includes', I.key, key);
      if (r.lower !== undefined) { const c = I.cmp(k, r.lower); if (c < 0 || (c === 0 && r.lowerOpen)) return false; }
      if (r.upper !== undefined) { const c = I.cmp(k, r.upper); if (c > 0 || (c === 0 && r.upperOpen)) return false; }
      return true;
    }
    static bound(lower, upper) {
      needArgs('IDBKeyRange', 'bound', 2, arguments.length);
      const lo = !!arguments[2], uo = !!arguments[3];
      const l = call('IDBKeyRange', 'bound', I.key, lower), u = call('IDBKeyRange', 'bound', I.key, upper);
      const c = I.cmp(l, u);
      if (c > 0) throw failed('IDBKeyRange', 'bound', 'DataError', 'The lower key is greater than the upper key.');
      if (c === 0 && (lo || uo)) throw failed('IDBKeyRange', 'bound', 'DataError', 'The lower key and upper key are equal and one of the bounds is open.');
      return new IDBKeyRange(T, l, u, lo, uo);
    }
    static lowerBound(bound) {
      needArgs('IDBKeyRange', 'lowerBound', 1, arguments.length);
      return new IDBKeyRange(T, call('IDBKeyRange', 'lowerBound', I.key, bound), undefined, !!arguments[1], true);
    }
    static only(value) {
      needArgs('IDBKeyRange', 'only', 1, arguments.length);
      const k = call('IDBKeyRange', 'only', I.key, value);
      return new IDBKeyRange(T, k, k, false, false);
    }
    static upperBound(bound) {
      needArgs('IDBKeyRange', 'upperBound', 1, arguments.length);
      return new IDBKeyRange(T, undefined, call('IDBKeyRange', 'upperBound', I.key, bound), true, !!arguments[1]);
    }
  }
  // A query as the native side takes it: undefined for everything, or
  // [lower, upper, lowerOpen, upperOpen].
  const rangeOf = (iface, method, q, nullMeansAll) => {
    if (q === undefined || (q === null && nullMeansAll)) return undefined;
    const r = q !== null && typeof q === 'object' ? ST.get(q) : undefined;
    if (r && r.kind === 'range') return [r.lower, r.upper, r.lowerOpen, r.upperOpen];
    if (q === null) throw failed(iface, method, 'DataError', 'No key or key range specified.');
    const k = call(iface, method, I.key, q);
    return [k, k, false, false];
  };

  // ---- IDBRecord ---------------------------------------------------------
  class IDBRecord {
    constructor(tok, key, primaryKey, value) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      const self = Object.create(new.target.prototype);
      ST.set(self, { kind: 'record', key, primaryKey, value });
      return self;
    }
    get key() { return state(this, 'record').key; }
    get primaryKey() { return state(this, 'record').primaryKey; }
    get value() { return state(this, 'record').value; }
  }

  // ---- events ------------------------------------------------------------
  class IDBVersionChangeEvent extends Ev {
    constructor(type) {
      if (arguments.length < 1) throw mkErr(TypeError, "Failed to construct 'IDBVersionChangeEvent': 1 argument required, but only 0 present.");
      const init = arguments[1];
      super(type, init);
      const o = init && init.oldVersion !== undefined ? Number(init.oldVersion) : 0;
      const n = init && init.newVersion !== undefined && init.newVersion !== null ? Number(init.newVersion) : null;
      ST.set(this, { kind: 'vce', oldVersion: o, newVersion: n });
    }
    get oldVersion() { return state(this, 'vce').oldVersion; }
    get newVersion() { return state(this, 'vce').newVersion; }
    get dataLoss() { state(this, 'vce'); return 'none'; }
    get dataLossMessage() { state(this, 'vce'); return ''; }
  }
  const fireVersion = (target, type, oldV, newV) => {
    const ev = new IDBVersionChangeEvent(type, { oldVersion: oldV, newVersion: newV });
    if (trust) trust(ev);
    return RA(ETdispatch, target, [ev]);
  };

  // ---- handler properties ---------------------------------------------------
  // `onsuccess` and friends: accessors on the prototype, as in Chrome.
  const handlers = (C, kind, names) => {
    for (const n of names) {
      const d = Object.getOwnPropertyDescriptor({
        get [n]() { const h = state(this, kind).on[n]; return h === undefined ? null : h; },
        set [n](v) { state(this, kind).on[n] = typeof v === 'function' || (v !== null && typeof v === 'object') ? v : null; },
      }, n);
      defineProperty(C.prototype, n, { get: d.get, set: d.set, enumerable: true, configurable: true });
    }
  };

  // ---- requests ----------------------------------------------------------
  class IDBRequest extends ET {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      super();
    }
    get result() {
      const s = state(this, 'req');
      if (s.ready !== 'done') throw dom('InvalidStateError', "Failed to read the 'result' property from 'IDBRequest': The request has not finished.");
      return s.result;
    }
    get error() {
      const s = state(this, 'req');
      if (s.ready !== 'done') throw dom('InvalidStateError', "Failed to read the 'error' property from 'IDBRequest': The request has not finished.");
      return s.error;
    }
    get source() { return state(this, 'req').source; }
    get transaction() { const s = state(this, 'req'); return s.tx ? s.tx.obj : null; }
    get readyState() { return state(this, 'req').ready; }
  }
  handlers(IDBRequest, 'req', ['onsuccess', 'onerror']);
  class IDBOpenDBRequest extends IDBRequest {
    constructor(tok) { super(tok); }
  }
  handlers(IDBOpenDBRequest, 'req', ['onblocked', 'onupgradeneeded']);

  const newRequest = (C, source, tx) => {
    const obj = new C(T);
    const s = { kind: 'req', obj, ready: 'pending', result: undefined, error: null, source, tx, on: {}, op: null };
    ST.set(obj, s);
    if (tx) parents.set(obj, tx.obj);
    return s;
  };

  // ---- connections, transactions -------------------------------------------
  const conns = new Set();            // open connections of this context
  const waiting = [];                 // transactions waiting for their stores
  const dbQueues = new Map();         // origin\0name -> [open/delete steps]

  const metaFrom = (info) => {
    const meta = new Map();
    if (!info) return meta;
    for (const [name, keyPath, autoInc, idx] of info[1]) {
      const indexes = new Map();
      for (const [iname, ikp, unique, multi] of idx) indexes.set(iname, { keyPath: ikp, unique, multi });
      meta.set(name, { keyPath, autoInc, indexes });
    }
    return meta;
  };
  const copyMeta = (meta) => {
    const out = new Map();
    for (const [n, m] of meta) out.set(n, { keyPath: m.keyPath, autoInc: m.autoInc, indexes: new Map(m.indexes) });
    return out;
  };

  const MODES = ['readonly', 'readwrite', 'versionchange'];
  const newTransaction = (conn, names, mode, durability) => {
    const obj = new IDBTransaction(T);
    const tx = { kind: 'tx', obj, conn, names, mode, durability, state: 'active', queue: [], id: 0, error: null,
      scheduled: false, processing: false, writes: 0, stores: new Map(), on: {}, done: null, oldMeta: null, oldVersion: 0, commitAsked: false };
    ST.set(obj, tx);
    parents.set(obj, conn.obj);
    conn.txs.add(tx);
    return tx;
  };
  const schedule = (tx) => {
    if (tx.scheduled || tx.state === 'finished') return;
    tx.scheduled = true;
    task(() => step(tx), 0);
  };
  // The engine task of a transaction: the end of the previous task makes it
  // inactive; then the next request is processed in a task of its own,
  // queued behind whatever the page queued meanwhile (in Chrome a result
  // comes back from the storage process, after timers already due), or the
  // transaction commits.
  const step = (tx) => {
    tx.scheduled = false;
    if (tx.state === 'finished') return;
    if (tx.state === 'active') tx.state = 'inactive';
    if (!tx.id) return;
    if (tx.queue.length) {
      // Nothing of the page's is waiting: no one can tell processing now
      // from processing in a task of its own.
      if (!tx.processing && !anyDue()) { process(tx); return; }
      if (!tx.processing) { tx.processing = true; task(() => { tx.processing = false; if (tx.state !== 'finished' && tx.queue.length) process(tx); else schedule(tx); }, 0); }
      return;
    }
    if (tx.state === 'inactive' || tx.state === 'committing') commit(tx);
  };
  const tryStart = (tx) => {
    if (tx.id || tx.state === 'finished') return true;
    const c = tx.conn;
    const id = I.begin(c.origin, c.name, tx.names, MODES.indexOf(tx.mode));
    if (!id) return false;
    tx.id = id;
    schedule(tx);
    return true;
  };
  const retryWaiting = () => {
    for (let i = 0; i < waiting.length; ) {
      if (tryStart(waiting[i])) waiting.splice(i, 1); else i++;
    }
    // Held by another page or worker: look again shortly.
    if (waiting.length && !retryWaiting.armed) {
      retryWaiting.armed = true;
      task(() => { retryWaiting.armed = false; retryWaiting(); }, 4);
    }
  };
  const finish = (tx) => {
    tx.state = 'finished';
    tx.conn.txs.delete(tx);
    for (const s of tx.queue) if (s.op && s.op.ticket) I.drop(s.op.ticket);
    tx.queue.length = 0;
    if (tx.conn.closePending && !tx.conn.txs.size) closed(tx.conn);
    retryWaiting();
    if (tx.done) { const d = tx.done; tx.done = null; d(tx); }
  };
  const commit = (tx) => {
    if (tx.state === 'finished') return;
    I.end(tx.id, true);
    finish(tx);
    fire(tx.obj, 'complete', false, false);
  };
  const ABORTED = 'The transaction was aborted, so the request cannot be fulfilled.';
  const abort = (tx, error) => {
    if (tx.state === 'finished') return;
    if (tx.id) I.end(tx.id, false);
    tx.error = error;
    if (tx.mode === 'versionchange' && tx.oldMeta) {
      tx.conn.meta = tx.oldMeta;
      tx.conn.version = tx.oldVersion;
      for (const [, store] of tx.stores) { const ss = ST.get(store); if (ss) ss.dead = !tx.conn.meta.has(ss.name); }
    }
    const pending = tx.queue.slice();
    finish(tx);
    // Each pending request fails, then the transaction reports the abort.
    task(() => {
      for (const s of pending) {
        s.ready = 'done'; s.result = undefined; s.error = dom('AbortError', ABORTED);
        fire(s.obj, 'error', true, true);
      }
      fire(tx.obj, 'abort', true, false);
    }, 0);
  };
  const UNCAUGHT = 'Uncaught exception in event handler.';
  // Run one request against the store and tell the page.
  const process = (tx) => {
    const s = tx.queue.shift();
    const op = s.op;
    let ok = true, result;
    try { result = op.run(tx.id, op); } catch (x) {
      ok = false;
      s.error = isArray(x) ? dom(x[0], x[1]) : x;
    }
    if (ok && result !== null && typeof result === 'object' && isArray(result.e)) {
      ok = false;
      s.error = dom(result.e[0], result.e[1]);
    }
    s.ready = 'done';
    if (ok) { s.result = op.done ? op.done(result) : result; s.error = null; } else s.result = undefined;
    tx.state = 'active';
    // Deactivation is the next task, queued before the handlers can queue
    // theirs: a timer set in `onsuccess` finds the transaction inactive.
    schedule(tx);
    const errs = reported();
    const notCancelled = fire(s.obj, ok ? 'success' : 'error', !ok, !ok);
    if (tx.state === 'finished') return;
    if (reported() !== errs) { abort(tx, dom('AbortError', UNCAUGHT)); return; }
    if (!ok && notCancelled) abort(tx, s.error);
  };
  const enqueue = (tx, s, op) => {
    s.op = op;
    tx.queue.push(s);
    schedule(tx);
    return s.obj;
  };
  // A transaction a method is called on must be live and active.
  const checkActive = (tx, iface, method) => {
    if (tx.state === 'finished') throw failed(iface, method, 'TransactionInactiveError', 'The transaction has finished.');
    if (tx.state !== 'active') throw failed(iface, method, 'TransactionInactiveError', 'The transaction is not active.');
  };
  const closed = (conn) => {
    conn.closed = true;
    conns.delete(conn);
    for (const w of conn.closeWaiters.splice(0)) w();
  };

  class IDBTransaction extends ET {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      super();
    }
    get objectStoreNames() {
      const tx = state(this, 'tx');
      return stringList(tx.mode === 'versionchange' ? [...tx.conn.meta.keys()] : tx.names);
    }
    get mode() { return state(this, 'tx').mode; }
    get durability() { return state(this, 'tx').durability; }
    get db() { return state(this, 'tx').conn.obj; }
    get error() { return state(this, 'tx').error; }
    abort() {
      const tx = state(this, 'tx');
      if (tx.state === 'finished' || tx.state === 'committing') throw failed('IDBTransaction', 'abort', 'InvalidStateError', 'The transaction has finished.');
      abort(tx, null);
    }
    commit() {
      const tx = state(this, 'tx');
      if (tx.state === 'finished' || tx.state === 'committing') throw failed('IDBTransaction', 'commit', 'InvalidStateError', 'The transaction has finished.');
      if (tx.state !== 'active') throw failed('IDBTransaction', 'commit', 'InvalidStateError', 'The transaction is not active.');
      tx.state = 'committing';
      schedule(tx);
    }
    objectStore(name) {
      const tx = state(this, 'tx');
      needArgs('IDBTransaction', 'objectStore', 1, arguments.length);
      name = String(name);
      if (tx.state === 'finished') throw failed('IDBTransaction', 'objectStore', 'InvalidStateError', 'The transaction has finished.');
      const inScope = tx.mode === 'versionchange' ? tx.conn.meta.has(name) : tx.names.indexOf(name) >= 0;
      if (!inScope) throw failed('IDBTransaction', 'objectStore', 'NotFoundError', 'The specified object store was not found.');
      return storeObject(tx, name);
    }
  }
  handlers(IDBTransaction, 'tx', ['onabort', 'oncomplete', 'onerror']);

  // ---- object stores, indexes ---------------------------------------------
  const storeObject = (tx, name) => {
    let o = tx.stores.get(name);
    if (o && !ST.get(o).dead) return o;
    o = new IDBObjectStore(T);
    ST.set(o, { kind: 'store', obj: o, tx, name, dead: false, indexes: new Map(), keyPathCache: undefined });
    tx.stores.set(name, o);
    return o;
  };
  const storeMeta = (s, iface, method) => {
    const m = s.tx.conn.meta.get(s.name);
    if (s.dead || !m) throw failed(iface, method, 'InvalidStateError', 'The object store has been deleted.');
    return m;
  };
  const pathValue = (p) => (isArray(p) ? p.slice() : p);

  // Read requests, shared by stores and indexes: kind as in `__pt_idbRead`.
  const readOp = (iface, method, s, index, range, kind, count, reverse, done) => {
    const store = s.kind === 'store' ? s : s.store;
    const tx = store.tx;
    storeMeta(store, iface, method);
    if (s.kind === 'index') indexMeta(s, iface, method);
    checkActive(tx, iface, method);
    const req = newRequest(IDBRequest, s.obj, tx);
    return enqueue(tx, req, { run: (id) => I.read(id, store.name, index, range, kind, count, reverse), done });
  };
  const records = (rows) => rows.map((r) => new IDBRecord(T, r[0], r[1], r[2]));
  const DIRS = ['next', 'nextunique', 'prev', 'prevunique'];
  // `getAll(query, count)` or `getAll({query, count, direction})`.
  const allArgs = (iface, method, args) => {
    const a0 = args[0];
    const isOptions = a0 !== null && typeof a0 === 'object' && !isArray(a0) && !ST.has(a0) &&
      !(a0 instanceof Date) && !ArrayBuffer.isView(a0) && !(a0 instanceof ArrayBuffer);
    if (isOptions) {
      const range = rangeOf(iface, method, a0.query, true);
      const count = a0.count === undefined ? 0 : ulong(iface, method, a0.count);
      const dir = a0.direction === undefined ? 'next' : enumValue(iface, method, a0.direction, DIRS, 'IDBCursorDirection');
      return [range, count, dir === 'prev' || dir === 'prevunique'];
    }
    const range = rangeOf(iface, method, a0, true);
    const count = args.length > 1 && args[1] !== undefined ? ulong(iface, method, args[1]) : 0;
    return [range, count, false];
  };

  const writeCheck = (s, iface, method) => {
    storeMeta(s, iface, method);
    checkActive(s.tx, iface, method);
    if (s.tx.mode === 'readonly') throw failed(iface, method, 'ReadOnlyError', 'The transaction is read-only.');
  };
  const putOp = (s, iface, method, value, key, hasKey, noOverwrite, source) => {
    const m = s.tx.conn.meta.get(s.name);
    writeCheck(s, iface, method);
    const ticket = call(iface, method, I.prepare, m.keyPath, m.autoInc, value, key, hasKey);
    const req = newRequest(IDBRequest, source || s.obj, s.tx);
    return enqueue(s.tx, req, { ticket, run: (id, op) => { s.tx.writes++; const r = I.put(id, s.name, op.ticket, noOverwrite); op.ticket = 0; return r; } });
  };

  class IDBObjectStore {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      return Object.create(new.target.prototype);
    }
    get name() { return state(this, 'store').name; }
    set name(v) {
      const s = state(this, 'store');
      const name = String(v);
      const tx = s.tx;
      storeMeta(s, 'IDBObjectStore', 'name');
      if (tx.mode !== 'versionchange') throw dom('InvalidStateError', "Failed to set the 'name' property on 'IDBObjectStore': The database is not running a version change transaction.");
      if (tx.state !== 'active') throw dom('TransactionInactiveError', "Failed to set the 'name' property on 'IDBObjectStore': The transaction is not active.");
      if (name === s.name) return;
      if (tx.conn.meta.has(name)) throw dom('ConstraintError', "Failed to set the 'name' property on 'IDBObjectStore': An object store with the specified name already exists.");
      I.schema(tx.id, 3, s.name, name);
      const m = tx.conn.meta.get(s.name);
      tx.conn.meta.delete(s.name);
      tx.conn.meta.set(name, m);
      tx.stores.delete(s.name);
      tx.stores.set(name, s.obj);
      s.name = name;
    }
    get keyPath() {
      const s = state(this, 'store');
      const m = s.tx.conn.meta.get(s.name);
      if (s.keyPathCache === undefined) s.keyPathCache = m ? pathValue(m.keyPath) : null;
      return s.keyPathCache;
    }
    get indexNames() {
      const s = state(this, 'store');
      const m = s.tx.conn.meta.get(s.name);
      return stringList(m ? [...m.indexes.keys()] : []);
    }
    get transaction() { return state(this, 'store').tx.obj; }
    get autoIncrement() { const s = state(this, 'store'); const m = s.tx.conn.meta.get(s.name); return !!(m && m.autoInc); }
    add(value) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'add', 1, arguments.length);
      return putOp(s, 'IDBObjectStore', 'add', value, arguments[1], arguments.length > 1 && arguments[1] !== undefined, true);
    }
    clear() {
      const s = state(this, 'store');
      writeCheck(s, 'IDBObjectStore', 'clear');
      const req = newRequest(IDBRequest, s.obj, s.tx);
      return enqueue(s.tx, req, { run: (id) => { s.tx.writes++; return I.remove(id, s.name, undefined, true); } });
    }
    count() {
      const s = state(this, 'store');
      const range = rangeOf('IDBObjectStore', 'count', arguments[0], true);
      return readOp('IDBObjectStore', 'count', s, null, range, 4, 0, false);
    }
    createIndex(name, keyPath) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'createIndex', 2, arguments.length);
      name = String(name);
      const opts = arguments[2] || {};
      const tx = s.tx;
      if (tx.mode !== 'versionchange') throw failed('IDBObjectStore', 'createIndex', 'InvalidStateError', 'The database is not running a version change transaction.');
      const m = storeMeta(s, 'IDBObjectStore', 'createIndex');
      checkActive(tx, 'IDBObjectStore', 'createIndex');
      if (m.indexes.has(name)) throw failed('IDBObjectStore', 'createIndex', 'ConstraintError', 'An index with the specified name already exists.');
      const kp = normPath(keyPath);
      if (kp === undefined || kp === null) throw failed('IDBObjectStore', 'createIndex', 'SyntaxError', 'The keyPath argument contains an invalid key path.');
      const unique = !!opts.unique, multi = !!opts.multiEntry;
      if (multi && isArray(kp)) throw failed('IDBObjectStore', 'createIndex', 'InvalidAccessError', 'The keyPath argument was an array and the multiEntry option is true.');
      const r = I.schema(tx.id, 4, s.name, name, kp, unique, multi);
      m.indexes.set(name, { keyPath: kp, unique, multi });
      // Existing records broke the uniqueness: the upgrade aborts.
      if (isArray(r)) task(() => abort(tx, dom(r[0], r[1])), 0);
      return indexObject(s, name);
    }
    delete(query) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'delete', 1, arguments.length);
      writeCheck(s, 'IDBObjectStore', 'delete');
      const range = rangeOf('IDBObjectStore', 'delete', query, false);
      const req = newRequest(IDBRequest, s.obj, s.tx);
      return enqueue(s.tx, req, { run: (id) => { s.tx.writes++; return I.remove(id, s.name, range, false); } });
    }
    deleteIndex(name) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'deleteIndex', 1, arguments.length);
      name = String(name);
      const tx = s.tx;
      if (tx.mode !== 'versionchange') throw failed('IDBObjectStore', 'deleteIndex', 'InvalidStateError', 'The database is not running a version change transaction.');
      const m = storeMeta(s, 'IDBObjectStore', 'deleteIndex');
      checkActive(tx, 'IDBObjectStore', 'deleteIndex');
      if (!m.indexes.has(name)) throw failed('IDBObjectStore', 'deleteIndex', 'NotFoundError', 'The specified index was not found.');
      I.schema(tx.id, 5, s.name, name);
      m.indexes.delete(name);
      const ix = s.indexes.get(name);
      if (ix) { ST.get(ix).dead = true; s.indexes.delete(name); }
    }
    get(query) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'get', 1, arguments.length);
      return readOp('IDBObjectStore', 'get', s, null, rangeOf('IDBObjectStore', 'get', query, false), 0, 0, false);
    }
    getAll() {
      const s = state(this, 'store');
      const [range, count, rev] = allArgs('IDBObjectStore', 'getAll', arguments);
      return readOp('IDBObjectStore', 'getAll', s, null, range, 2, count, rev);
    }
    getAllKeys() {
      const s = state(this, 'store');
      const [range, count, rev] = allArgs('IDBObjectStore', 'getAllKeys', arguments);
      return readOp('IDBObjectStore', 'getAllKeys', s, null, range, 3, count, rev);
    }
    getAllRecords() {
      const s = state(this, 'store');
      const o = arguments[0] || {};
      const [range, count, rev] = allArgs('IDBObjectStore', 'getAllRecords', [Object.assign({}, o)]);
      return readOp('IDBObjectStore', 'getAllRecords', s, null, range, 5, count, rev, records);
    }
    getKey(query) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'getKey', 1, arguments.length);
      return readOp('IDBObjectStore', 'getKey', s, null, rangeOf('IDBObjectStore', 'getKey', query, false), 1, 0, false);
    }
    index(name) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'index', 1, arguments.length);
      name = String(name);
      const m = storeMeta(s, 'IDBObjectStore', 'index');
      if (s.tx.state === 'finished') throw failed('IDBObjectStore', 'index', 'InvalidStateError', 'The transaction has finished.');
      if (!m.indexes.has(name)) throw failed('IDBObjectStore', 'index', 'NotFoundError', 'The specified index was not found.');
      return indexObject(s, name);
    }
    openCursor() { return openCursor(state(this, 'store'), 'IDBObjectStore', 'openCursor', arguments, true); }
    openKeyCursor() { return openCursor(state(this, 'store'), 'IDBObjectStore', 'openKeyCursor', arguments, false); }
    put(value) {
      const s = state(this, 'store');
      needArgs('IDBObjectStore', 'put', 1, arguments.length);
      return putOp(s, 'IDBObjectStore', 'put', value, arguments[1], arguments.length > 1 && arguments[1] !== undefined, false);
    }
  }

  const indexObject = (store, name) => {
    let o = store.indexes.get(name);
    if (o && !ST.get(o).dead) return o;
    o = new IDBIndex(T);
    ST.set(o, { kind: 'index', obj: o, store, name, dead: false, keyPathCache: undefined });
    store.indexes.set(name, o);
    return o;
  };
  const indexMeta = (x, iface, method) => {
    const sm = x.store.tx.conn.meta.get(x.store.name);
    const m = sm && sm.indexes.get(x.name);
    if (x.dead || x.store.dead || !m) throw failed(iface, method, 'InvalidStateError', 'The index or its object store has been deleted.');
    return m;
  };

  class IDBIndex {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      return Object.create(new.target.prototype);
    }
    get name() { return state(this, 'index').name; }
    set name(v) {
      const x = state(this, 'index');
      const name = String(v);
      const tx = x.store.tx;
      const sm = tx.conn.meta.get(x.store.name);
      indexMeta(x, 'IDBIndex', 'name');
      if (tx.mode !== 'versionchange') throw dom('InvalidStateError', "Failed to set the 'name' property on 'IDBIndex': The database is not running a version change transaction.");
      if (tx.state !== 'active') throw dom('TransactionInactiveError', "Failed to set the 'name' property on 'IDBIndex': The transaction is not active.");
      if (name === x.name) return;
      if (sm.indexes.has(name)) throw dom('ConstraintError', "Failed to set the 'name' property on 'IDBIndex': An index with the specified name already exists.");
      I.schema(tx.id, 6, x.store.name, x.name, name);
      sm.indexes.set(name, sm.indexes.get(x.name));
      sm.indexes.delete(x.name);
      x.store.indexes.delete(x.name);
      x.store.indexes.set(name, x.obj);
      x.name = name;
    }
    get objectStore() { return state(this, 'index').store.obj; }
    get keyPath() {
      const x = state(this, 'index');
      if (x.keyPathCache === undefined) { const sm = x.store.tx.conn.meta.get(x.store.name); const m = sm && sm.indexes.get(x.name); x.keyPathCache = m ? pathValue(m.keyPath) : null; }
      return x.keyPathCache;
    }
    get multiEntry() { const x = state(this, 'index'); const sm = x.store.tx.conn.meta.get(x.store.name); const m = sm && sm.indexes.get(x.name); return !!(m && m.multi); }
    get unique() { const x = state(this, 'index'); const sm = x.store.tx.conn.meta.get(x.store.name); const m = sm && sm.indexes.get(x.name); return !!(m && m.unique); }
    count() {
      const x = state(this, 'index');
      return readOp('IDBIndex', 'count', x, x.name, rangeOf('IDBIndex', 'count', arguments[0], true), 4, 0, false);
    }
    get(query) {
      const x = state(this, 'index');
      needArgs('IDBIndex', 'get', 1, arguments.length);
      return readOp('IDBIndex', 'get', x, x.name, rangeOf('IDBIndex', 'get', query, false), 0, 0, false);
    }
    getAll() {
      const x = state(this, 'index');
      const [range, count, rev] = allArgs('IDBIndex', 'getAll', arguments);
      return readOp('IDBIndex', 'getAll', x, x.name, range, 2, count, rev);
    }
    getAllKeys() {
      const x = state(this, 'index');
      const [range, count, rev] = allArgs('IDBIndex', 'getAllKeys', arguments);
      return readOp('IDBIndex', 'getAllKeys', x, x.name, range, 3, count, rev);
    }
    getAllRecords() {
      const x = state(this, 'index');
      const [range, count, rev] = allArgs('IDBIndex', 'getAllRecords', [Object.assign({}, arguments[0] || {})]);
      return readOp('IDBIndex', 'getAllRecords', x, x.name, range, 5, count, rev, records);
    }
    getKey(query) {
      const x = state(this, 'index');
      needArgs('IDBIndex', 'getKey', 1, arguments.length);
      return readOp('IDBIndex', 'getKey', x, x.name, rangeOf('IDBIndex', 'getKey', query, false), 1, 0, false);
    }
    openCursor() { return openCursor(state(this, 'index'), 'IDBIndex', 'openCursor', arguments, true); }
    openKeyCursor() { return openCursor(state(this, 'index'), 'IDBIndex', 'openKeyCursor', arguments, false); }
  }

  // ---- cursors -------------------------------------------------------------
  const ITERATED = 'The cursor is being iterated or has iterated past its end.';
  const openCursor = (src, iface, method, args, withValue) => {
    const store = src.kind === 'store' ? src : src.store;
    storeMeta(store, iface, method);
    if (src.kind === 'index') indexMeta(src, iface, method);
    checkActive(store.tx, iface, method);
    const range = rangeOf(iface, method, args[0], true);
    const dir = args.length > 1 && args[1] !== undefined ? enumValue(iface, method, args[1], DIRS, 'IDBCursorDirection') : 'next';
    const req = newRequest(IDBRequest, src.obj, store.tx);
    const obj = withValue ? new IDBCursorWithValue(T) : new IDBCursor(T);
    const c = { kind: 'cursor', obj, src, store, index: src.kind === 'index' ? src.name : null, range, dir, dirNum: DIRS.indexOf(dir),
      req, withValue, key: undefined, primaryKey: undefined, value: undefined, posKey: undefined, posPrimary: undefined, got: false,
      buf: null, bi: 0, bufWrites: 0, batch: 1 };
    ST.set(obj, c);
    return enqueue(store.tx, req, cursorOp(c, undefined, undefined, 0));
  };
  // Records come in batches, as Chrome prefetches: the first fetch takes
  // one (a page may read a single record), each plain `continue()` doubles
  // the next batch up to 256. A jump (`continue(key)`, `advance`) or any
  // write in the transaction drops what was fetched ahead.
  const cursorOp = (c, target, targetPrimary, skip) => ({
    run: (id) => {
      const tx = c.store.tx;
      const plain = target === undefined && targetPrimary === undefined && skip === 0;
      if (plain && c.buf && c.bi < c.buf.length && c.bufWrites === tx.writes) {
        const i = c.bi; c.bi += 5;
        return c.buf.slice(i, i + 5);
      }
      const n = plain && c.buf ? (c.batch = Math.min(c.batch * 2, 256)) : 1;
      const rows = I.cursor(id, c.store.name, c.index, c.range, c.dirNum, c.posKey, c.posPrimary, target, targetPrimary, skip, c.withValue, n);
      if (!rows || !rows.length) { c.buf = null; return null; }
      c.buf = rows; c.bi = 5; c.bufWrites = tx.writes;
      return rows.length === 5 ? rows : rows.slice(0, 5);
    },
    done: (row) => {
      if (row === null || row === undefined) { c.key = c.primaryKey = c.value = undefined; c.got = false; return null; }
      c.key = row[0]; c.primaryKey = row[1]; c.value = row[2]; c.posKey = row[3]; c.posPrimary = row[4]; c.got = true;
      return c.obj;
    },
  });
  const cursorCheck = (c, iface, method) => {
    const tx = c.store.tx;
    checkActive(tx, iface, method);
    if (c.store.dead || (c.src.kind === 'index' && c.src.dead)) throw failed(iface, method, 'InvalidStateError', 'The cursor\'s source or effective object store has been deleted.');
  };
  const iterate = (c, target, targetPrimary, skip) => {
    c.got = false;
    c.req.ready = 'pending';
    enqueue(c.store.tx, c.req, cursorOp(c, target, targetPrimary, skip));
  };

  class IDBCursor {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      return Object.create(new.target.prototype);
    }
    get source() { return state(this, 'cursor').src.obj; }
    get direction() { return state(this, 'cursor').dir; }
    get key() { return state(this, 'cursor').key; }
    get primaryKey() { return state(this, 'cursor').primaryKey; }
    get request() { return state(this, 'cursor').req.obj; }
    advance(count) {
      const c = state(this, 'cursor');
      needArgs('IDBCursor', 'advance', 1, arguments.length);
      const n = Number(count);
      if (!Number.isFinite(n) || n < 0 || n > 4294967295) throw typeErr('IDBCursor', 'advance', "Value is outside the 'unsigned long' value range.");
      if (Math.trunc(n) === 0) throw typeErr('IDBCursor', 'advance', 'A count argument with value 0 (zero) was supplied, must be greater than 0.');
      cursorCheck(c, 'IDBCursor', 'advance');
      if (!c.got) throw failed('IDBCursor', 'advance', 'InvalidStateError', ITERATED);
      iterate(c, undefined, undefined, Math.trunc(n) - 1);
    }
    continue() {
      const c = state(this, 'cursor');
      cursorCheck(c, 'IDBCursor', 'continue');
      if (!c.got) throw failed('IDBCursor', 'continue', 'InvalidStateError', ITERATED);
      let target;
      if (arguments.length && arguments[0] !== undefined) {
        target = call('IDBCursor', 'continue', I.key, arguments[0]);
        const cmp = I.cmp(target, c.key);
        const fwd = c.dirNum < 2;
        if (fwd && cmp <= 0) throw failed('IDBCursor', 'continue', 'DataError', "The parameter is less than or equal to this cursor's position.");
        if (!fwd && cmp >= 0) throw failed('IDBCursor', 'continue', 'DataError', "The parameter is greater than or equal to this cursor's position.");
      }
      iterate(c, target, undefined, 0);
    }
    continuePrimaryKey(key, primaryKey) {
      const c = state(this, 'cursor');
      needArgs('IDBCursor', 'continuePrimaryKey', 2, arguments.length);
      cursorCheck(c, 'IDBCursor', 'continuePrimaryKey');
      if (c.src.kind !== 'index') throw failed('IDBCursor', 'continuePrimaryKey', 'InvalidAccessError', "The cursor's source is not an index.");
      if (c.dir !== 'next' && c.dir !== 'prev') throw failed('IDBCursor', 'continuePrimaryKey', 'InvalidAccessError', "The cursor's direction is not 'next' or 'prev'.");
      if (!c.got) throw failed('IDBCursor', 'continuePrimaryKey', 'InvalidStateError', ITERATED);
      const k = call('IDBCursor', 'continuePrimaryKey', I.key, key);
      const p = call('IDBCursor', 'continuePrimaryKey', I.key, primaryKey);
      const ck = I.cmp(k, c.key), cp = I.cmp(p, c.primaryKey);
      if (c.dir === 'next' && (ck < 0 || (ck === 0 && cp <= 0))) throw failed('IDBCursor', 'continuePrimaryKey', 'DataError', "The parameter is less than or equal to this cursor's position.");
      if (c.dir === 'prev' && (ck > 0 || (ck === 0 && cp >= 0))) throw failed('IDBCursor', 'continuePrimaryKey', 'DataError', "The parameter is greater than or equal to this cursor's position.");
      iterate(c, k, p, 0);
    }
    delete() {
      const c = state(this, 'cursor');
      const tx = c.store.tx;
      checkActive(tx, 'IDBCursor', 'delete');
      if (tx.mode === 'readonly') throw failed('IDBCursor', 'delete', 'ReadOnlyError', 'The record may not be deleted inside a read-only transaction.');
      cursorCheck(c, 'IDBCursor', 'delete');
      if (!c.got || !c.withValue) throw failed('IDBCursor', 'delete', 'InvalidStateError', c.withValue ? ITERATED : 'The cursor is a key cursor.');
      const pk = c.primaryKey;
      const req = newRequest(IDBRequest, c.obj, tx);
      return enqueue(tx, req, { run: (id) => { tx.writes++; return I.remove(id, c.store.name, [pk, pk, false, false], false); } });
    }
    update(value) {
      const c = state(this, 'cursor');
      needArgs('IDBCursor', 'update', 1, arguments.length);
      const tx = c.store.tx;
      checkActive(tx, 'IDBCursor', 'update');
      if (tx.mode === 'readonly') throw failed('IDBCursor', 'update', 'ReadOnlyError', 'The record may not be updated inside a read-only transaction.');
      cursorCheck(c, 'IDBCursor', 'update');
      if (!c.got || !c.withValue) throw failed('IDBCursor', 'update', 'InvalidStateError', c.withValue ? ITERATED : 'The cursor is a key cursor.');
      const m = storeMeta(c.store, 'IDBCursor', 'update');
      if (m.keyPath !== null) {
        const clone = call('IDBCursor', 'update', I.clone, value);
        let k;
        try { k = I.keyOf(m.keyPath, clone); } catch (x) { k = undefined; }
        if (k === undefined || I.cmp(k, c.primaryKey) !== 0) throw failed('IDBCursor', 'update', 'DataError', "The effective object store of this cursor uses in-line keys and evaluating the key path of the value parameter results in a different value than the cursor's effective key.");
        return putOp(c.store, 'IDBCursor', 'update', clone, undefined, false, false, c.obj);
      }
      return putOp(c.store, 'IDBCursor', 'update', value, c.primaryKey, true, false, c.obj);
    }
  }
  class IDBCursorWithValue extends IDBCursor {
    constructor(tok) { super(tok); }
    get value() { return state(this, 'cursor').value; }
  }

  // ---- IDBDatabase ---------------------------------------------------------
  class IDBDatabase extends ET {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      super();
    }
    get name() { return state(this, 'conn').name; }
    get version() { return state(this, 'conn').version; }
    get objectStoreNames() { return stringList([...state(this, 'conn').meta.keys()]); }
    close() {
      const c = state(this, 'conn');
      c.closePending = true;
      if (!c.txs.size) closed(c);
    }
    createObjectStore(name) {
      const c = state(this, 'conn');
      needArgs('IDBDatabase', 'createObjectStore', 1, arguments.length);
      name = String(name);
      const opts = arguments[1] || {};
      const tx = c.upgrade;
      if (!tx || tx.state === 'finished') throw failed('IDBDatabase', 'createObjectStore', 'InvalidStateError', 'The database is not running a version change transaction.');
      checkActive(tx, 'IDBDatabase', 'createObjectStore');
      const kp = normPath(opts.keyPath);
      if (kp === undefined) throw failed('IDBDatabase', 'createObjectStore', 'SyntaxError', 'The keyPath option is not a valid key path.');
      if (c.meta.has(name)) throw failed('IDBDatabase', 'createObjectStore', 'ConstraintError', 'An object store with the specified name already exists.');
      const autoInc = !!opts.autoIncrement;
      if (autoInc && (kp === '' || isArray(kp))) throw failed('IDBDatabase', 'createObjectStore', 'InvalidAccessError', 'The autoIncrement option was set but the keyPath option was empty or an array.');
      I.schema(tx.id, 1, name, kp, autoInc);
      c.meta.set(name, { keyPath: kp, autoInc, indexes: new Map() });
      return storeObject(tx, name);
    }
    deleteObjectStore(name) {
      const c = state(this, 'conn');
      needArgs('IDBDatabase', 'deleteObjectStore', 1, arguments.length);
      name = String(name);
      const tx = c.upgrade;
      if (!tx || tx.state === 'finished') throw failed('IDBDatabase', 'deleteObjectStore', 'InvalidStateError', 'The database is not running a version change transaction.');
      checkActive(tx, 'IDBDatabase', 'deleteObjectStore');
      if (!c.meta.has(name)) throw failed('IDBDatabase', 'deleteObjectStore', 'NotFoundError', 'The specified object store was not found.');
      I.schema(tx.id, 2, name);
      c.meta.delete(name);
      const o = tx.stores.get(name);
      if (o) { ST.get(o).dead = true; tx.stores.delete(name); }
    }
    transaction(storeNames) {
      const c = state(this, 'conn');
      needArgs('IDBDatabase', 'transaction', 1, arguments.length);
      const mode = arguments.length > 1 && arguments[1] !== undefined ? enumValue('IDBDatabase', 'transaction', arguments[1], ['readonly', 'readwrite', 'versionchange'], 'IDBTransactionMode') : 'readonly';
      const o = arguments[2];
      let durability = 'default';
      if (o !== undefined && o !== null && o.durability !== undefined) {
        const d = String(o.durability);
        if (['default', 'strict', 'relaxed'].indexOf(d) < 0) throw typeErr('IDBDatabase', 'transaction', "Failed to read the 'durability' property from 'IDBTransactionOptions': The provided value '" + d + "' is not a valid enum value of type IDBTransactionDurability.");
        durability = d;
      }
      if (c.upgrade && c.upgrade.state !== 'finished') throw failed('IDBDatabase', 'transaction', 'InvalidStateError', 'A version change transaction is running.');
      if (c.closePending) throw failed('IDBDatabase', 'transaction', 'InvalidStateError', 'The database connection is closing.');
      let names;
      if (typeof storeNames === 'string') names = [storeNames];
      else if (storeNames !== null && typeof storeNames === 'object' && typeof storeNames[Symbol.iterator] === 'function') names = Array.from(storeNames, String);
      else names = [String(storeNames)];
      names = [...new Set(names)].sort();
      for (const n of names) if (!c.meta.has(n)) throw failed('IDBDatabase', 'transaction', 'NotFoundError', 'One of the specified object stores was not found.');
      if (!names.length) throw failed('IDBDatabase', 'transaction', 'InvalidAccessError', 'The storeNames parameter was empty.');
      if (mode === 'versionchange') throw typeErr('IDBDatabase', 'transaction', "The provided value 'versionchange' is not a valid enum value of type IDBTransactionMode.");
      const tx = newTransaction(c, names, mode, durability);
      if (!tryStart(tx)) waiting.push(tx);
      schedule(tx);
      return tx.obj;
    }
  }
  handlers(IDBDatabase, 'conn', ['onabort', 'onclose', 'onerror', 'onversionchange']);

  const newConnection = (origin, name, info) => {
    const obj = new IDBDatabase(T);
    const c = { kind: 'conn', obj, origin, name, version: info ? info[0] : 0, meta: metaFrom(info), txs: new Set(),
      closePending: false, closed: false, closeWaiters: [], upgrade: null, on: {} };
    ST.set(obj, c);
    conns.add(c);
    return c;
  };

  // ---- the factory -----------------------------------------------------------
  // Opens and deletes of one database run one after another.
  const enqueueDb = (key, run) => {
    let q = dbQueues.get(key);
    if (!q) { q = []; dbQueues.set(key, q); }
    q.push(run);
    if (q.length === 1) task(() => run(() => nextDb(key)), 0);
  };
  const nextDb = (key) => {
    const q = dbQueues.get(key);
    if (!q) return;
    q.shift();
    if (!q.length) { dbQueues.delete(key); return; }
    const run = q[0];
    task(() => run(() => nextDb(key)), 0);
  };
  // Tell the other open connections a version change or delete is coming,
  // then wait for them to close.
  const settleOthers = (origin, name, req, oldV, newV, then) => {
    const others = [...conns].filter((c) => c.origin === origin && c.name === name && !c.closePending);
    for (const c of others) if (!c.closePending) fireVersion(c.obj, 'versionchange', oldV, newV);
    const open = others.filter((c) => !c.closed);
    if (!open.length) { then(); return; }
    fireVersion(req.obj, 'blocked', oldV, newV);
    let left = open.length;
    for (const c of open) c.closeWaiters.push(() => { if (--left === 0) then(); });
  };
  const requestDone = (req, result, error) => {
    req.ready = 'done'; req.result = result; req.error = error;
  };
  const beginUpgrade = (origin, name, then) => {
    const id = I.begin(origin, name, [], 2);
    if (id) { then(id); return; }
    task(() => beginUpgrade(origin, name, then), 4);
  };
  const runOpen = (req, origin, name, version, next) => {
    const info = I.info(origin, name);
    const cur = info ? info[0] : 0;
    const v = version === undefined ? (cur || 1) : version;
    if (v < cur) {
      requestDone(req, undefined, dom('VersionError', 'The requested version (' + v + ') is less than the existing version (' + cur + ').'));
      fire(req.obj, 'error', true, true);
      next();
      return;
    }
    if (v === cur) {
      const conn = newConnection(origin, name, info);
      requestDone(req, conn.obj, null);
      fire(req.obj, 'success', false, false);
      next();
      return;
    }
    settleOthers(origin, name, req, cur, v, () => beginUpgrade(origin, name, (id) => {
      const conn = newConnection(origin, name, I.info(origin, name));
      const tx = newTransaction(conn, [], 'versionchange', 'default');
      tx.id = id;
      tx.oldMeta = copyMeta(conn.meta);
      tx.oldVersion = conn.version;
      I.schema(id, 0, v);
      conn.version = v;
      conn.upgrade = tx;
      req.tx = tx;
      requestDone(req, conn.obj, null);
      tx.done = () => { conn.upgrade = null; req.tx = null; };
      // The upgrade transaction's end decides the open request's outcome.
      const completeOrAbort = () => {
        tx.obj.addEventListener('complete', () => {
          if (conn.closePending && !conn.closed) {
            requestDone(req, undefined, dom('AbortError', 'The connection was closed.'));
            fire(req.obj, 'error', true, true);
          } else fire(req.obj, 'success', false, false);
          next();
        });
        tx.obj.addEventListener('abort', () => {
          if (!conn.closed) closed(conn);
          requestDone(req, undefined, dom('AbortError', 'Version change transaction was aborted in upgradeneeded event handler.'));
          fire(req.obj, 'error', true, true);
          next();
        });
      };
      completeOrAbort();
      tx.state = 'active';
      schedule(tx);
      const errs = reported();
      fireVersion(req.obj, 'upgradeneeded', cur, v);
      if (reported() !== errs) abort(tx, dom('AbortError', UNCAUGHT));
    }));
  };
  const runDelete = (req, origin, name, next) => {
    const info = I.info(origin, name);
    const cur = info ? info[0] : 0;
    settleOthers(origin, name, req, cur, null, () => {
      const old = I.deleteDb(origin, name);
      requestDone(req, undefined, null);
      fireVersion(req.obj, 'success', old === null ? 0 : old, null);
      next();
    });
  };

  class IDBFactory {
    constructor(tok) {
      if (tok !== T) throw mkErr(TypeError, 'Illegal constructor');
      const self = Object.create(new.target.prototype);
      ST.set(self, { kind: 'factory' });
      return self;
    }
    cmp(first, second) {
      state(this, 'factory');
      needArgs('IDBFactory', 'cmp', 2, arguments.length);
      return call('IDBFactory', 'cmp', I.cmp, first, second);
    }
    databases() {
      state(this, 'factory');
      let origin;
      try { origin = checkOrigin('databases'); } catch (e) { return PromiseC.reject(e); }
      const rows = I.list(origin);
      return PromiseC.resolve(rows.map((r) => ({ name: r[0], version: r[1] })));
    }
    deleteDatabase(name) {
      state(this, 'factory');
      needArgs('IDBFactory', 'deleteDatabase', 1, arguments.length);
      name = String(name);
      const origin = checkOrigin('deleteDatabase');
      const req = newRequest(IDBOpenDBRequest, null, null);
      enqueueDb(origin + '\u0000' + name, (next) => runDelete(req, origin, name, next));
      return req.obj;
    }
    open(name) {
      state(this, 'factory');
      needArgs('IDBFactory', 'open', 1, arguments.length);
      name = String(name);
      let version;
      if (arguments.length > 1 && arguments[1] !== undefined) {
        const n = Number(arguments[1]);
        if (!Number.isFinite(n) || n < 0 || n > 9007199254740991) throw typeErr('IDBFactory', 'open', "Value is outside the 'unsigned long long' value range.");
        version = Math.trunc(n);
        if (version === 0) throw typeErr('IDBFactory', 'open', 'The version provided must not be 0.');
      }
      const origin = checkOrigin('open');
      const req = newRequest(IDBOpenDBRequest, null, null);
      enqueueDb(origin + '\u0000' + name, (next) => runOpen(req, origin, name, version, next));
      return req.obj;
    }
  }

  // Chrome's members are enumerable, and each prototype names itself.
  for (const C of [DOMStringList, IDBKeyRange, IDBRecord, IDBVersionChangeEvent, IDBRequest, IDBOpenDBRequest, IDBTransaction,
    IDBObjectStore, IDBIndex, IDBCursor, IDBCursorWithValue, IDBDatabase, IDBFactory]) {
    const P = C.prototype;
    for (const k of Object.getOwnPropertyNames(P)) {
      if (k === 'constructor') continue;
      const d = Object.getOwnPropertyDescriptor(P, k);
      d.enumerable = true;
      defineProperty(P, k, d);
    }
    defineProperty(P, Symbol.toStringTag, { value: C.name, configurable: true });
  }
  for (const k of ['bound', 'lowerBound', 'only', 'upperBound']) {
    const d = Object.getOwnPropertyDescriptor(IDBKeyRange, k);
    d.enumerable = true;
    defineProperty(IDBKeyRange, k, d);
  }
  for (const C of [DOMStringList, IDBKeyRange, IDBRecord, IDBVersionChangeEvent, IDBRequest, IDBOpenDBRequest, IDBTransaction,
    IDBObjectStore, IDBIndex, IDBCursor, IDBCursorWithValue, IDBDatabase, IDBFactory]) {
    defineProperty(G, C.name, { value: C, writable: true, enumerable: false, configurable: true });
  }
  const factory = new IDBFactory(T);
  defineProperty(G, 'indexedDB', { value: factory, writable: true, enumerable: true, configurable: true });
})();
