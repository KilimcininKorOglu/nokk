// Pure-JS DOM runtime for the nokk engine.
//
// Runs once per V8 context, after the stealth environment bootstrap. Defines a
// minimal but real DOM (Node/Element/Text/Comment/Document, events, selectors)
// entirely as JS objects — no native bindings. The Rust side hands over a parsed
// tree via __pt_installDocument(tree); page scripts then see a normal `document`.
//
// Scope: enough for typical page and fingerprint scripts. No layout, no
// rendering, no CSS cascade. Selector support: tag, #id, .class, [attr],
// [attr=val], *, plus descendant (space) and child (>) combinators and comma
// lists.
(() => {
  // Снимок JSON, снятый до единой строки страницы. Движок сериализует свои
  // очереди сам, и если делать это через `JSON.stringify` страницы, то страница,
  // подменив его, увидит внутренности эмулятора — трафика такого вида в браузере
  // нет вовсе, и это улика не хуже отсутствующего свойства.
  const __ptJSON = globalThis.__ptJSON || { stringify: JSON.stringify, parse: JSON.parse };
  const ELEMENT_NODE = 1, TEXT_NODE = 3, COMMENT_NODE = 8,
        DOCUMENT_NODE = 9, DOCUMENT_FRAGMENT_NODE = 11;

  const __pt_soon = (f) => { try { queueMicrotask(f); } catch (e) { setTimeout(f, 0); } };
  const VOID = new Set(['area','base','br','col','embed','hr','img','input',
    'link','meta','param','source','track','wbr']);

  // Every node in a subtree, shadow trees included. Frames and scripts come to
  // life as part of whatever tree they are inserted with — a widget hands the DOM
  // a finished tree, not a bare element.
  function __attrName(el, n) {
    const s = String(n);
    return el.__ptNS === undefined || el.__ptNS === 'http://www.w3.org/1999/xhtml' ? s.toLowerCase() : s;
  }
  function __walkTree(node, fn) {
    if (!node) return;
    fn(node);
    const kids = node.__ptKids;
    if (kids) for (const c of kids.slice()) __walkTree(c, fn);
    if (node.__ptShadow) __walkTree(node.__ptShadow, fn);
  }

  // What connecting a subtree means for the elements that *do* something: a frame
  // opens a browsing context, a script runs. Both were inert before — a page that
  // builds `<script src=…>` and appends it (which is how every tag loader, widget
  // bootstrap and anti-bot orchestrator works, Cloudflare's interstitial included)
  // got a DOM node and nothing else: no fetch, no execution, no `onload`.
  const __connectSubtree = (node) => __walkTree(node, (n) => {
    if (n.__ptLocal === 'iframe') n.__ptConnectFrame();
    else if (n.__ptLocal === 'script') n.__ptRunScript();
    // Стиль и предзагрузка тоже начинают грузиться с попадания в документ, а
    // не с присваивания `href`: порядок бывает любой.
    else if (n.__ptLocal === 'link' && n.__ptLoadLink) n.__ptLoadLink();
    else if (n.__ptLocal === 'img' && n.__ptLoadImage) n.__ptLoadImage();
    if (n.nodeType === ELEMENT_NODE && __customs.has(n.__ptLocal)) {
      if (!n.__ptUpgraded) __customUpgrade(n, __customs.get(n.__ptLocal));
      else __customCallback(n, 'connectedCallback');
    }
  });

  // Массив в обёртке HTMLCollection: length/item/namedItem/итератор, но не Array.
  // Страницы читают `.length` и перебирают — этого достаточно, а `Array.isArray`
  // на настоящей коллекции ложен, как и должно быть.
  function __collection(arr) {
    const list = Object.create(__link('HTMLCollection', __collectionProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }
  // `querySelectorAll` отдаёт NodeList — не живой, как у childNodes, а слепок;
  // это разные вещи в браузере и разные ответы на `Object.prototype.toString`.
  function __staticNodeList(arr) {
    const list = Object.create(__link('NodeList', __nodeListProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }
  // childNodes отдаёт NodeList, а не массив: `Array.isArray(node.childNodes)`
  // на платформе ложен, и сборщик отпечатков Turnstile метит массив отдельной
  // категорией. Список живой и тождественный самому себе — виджеты сравнивают
  // `a.childNodes === a.childNodes`, — поэтому он кэшируется на узле, а индексы
  // пересобираются при каждом обращении.
  function __nodeList(node) {
    const proto = __link('NodeList', __nodeListProto);
    let list = node.__ptList;
    if (!list) {
      list = Object.create(proto);
      Object.defineProperty(node, '__ptList', { value: list, enumerable: false, writable: true });
    }
    const kids = node.__ptKids, prev = list.__ptLen | 0;
    for (let i = 0; i < kids.length; i++) list[i] = kids[i];
    for (let i = kids.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, '__ptLen', { value: kids.length, enumerable: false, configurable: true });
    return list;
  }
  // Прототип связывается со своим интерфейсом при первом обращении: интерфейсы
  // объявляются позже этого файла, а список создаётся уже на странице. Члены
  // переезжают на `Iface.prototype`, а наш объект становится его наследником —
  // так `list instanceof NodeList` истинно, и `constructor` тот, что нужно.
  // Возвращает прототип, на котором надо строить сам список. Раньше члены
  // переезжали на интерфейс, а пустая заготовка оставалась в цепочке лишним
  // уровнем: у Chrome `Object.getPrototypeOf(document.querySelectorAll('*'))`
  // это сам `NodeList.prototype`, а у нас — пустой объект перед ним. Так было у
  // всех списков разом, и любой обход прототипов это видел.
  const __ptHiddenFrame = () => {
    if (!globalThis.__pt_crossSite) return false;
    let w = globalThis;
    for (let i = 0; i < 8 && w; i++) {
      if (typeof w.innerWidth !== 'number') break;
      if ((w.innerWidth | 0) === 0 && (w.innerHeight | 0) === 0) return true;
      let p = null;
      try { p = w.parent; } catch (e) { break; }
      if (!p || p === w) break;
      w = p;
    }
    return false;
  };
  // Прокси с проверкой цикла прототипов (см. __pt_proxy в прологе).
  const __ptProxy = (target, handler) => {
    if (typeof globalThis.__pt_proxy === 'function') return globalThis.__pt_proxy(target, handler);
    const px = new Proxy(target, handler);
    handler.setPrototypeOf = (t, proto) => {
      for (let q = proto, i = 0; q !== null && q !== undefined && i < 100000; i++) {
        if (q === t || q === px) throw new TypeError('Cyclic __proto__ value');
        q = Object.getPrototypeOf(q);
      }
      return Reflect.setPrototypeOf(t, proto);
    };
    return px;
  };
  const __link = (name, proto) => {
    const I = globalThis[name];
    if (!I || !I.prototype) return proto;
    if (proto.__ptLinked) return I.prototype;
    proto.__ptLinked = true;
    // Связывание идёт уже после натурализации бутстрапа — перенесённые члены
    // маскируем сами, иначе `HTMLCollection.prototype.item` показывал исходник.
    const nat = globalThis.__pt_native || ((f) => f);
    const named = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return nat(f); };
    for (const k of Reflect.ownKeys(proto)) {
      if (k === '__ptLinked') continue;
      const d = Object.getOwnPropertyDescriptor(proto, k);
      const label = typeof k === 'symbol' ? '[' + (k.description || '') + ']' : k;
      // Под символом часто стоит чужая встроенная функция (итератор списков —
      // сам Array.prototype.values): у Chrome её имя остаётся «values».
      if (typeof d.value === 'function' && !(typeof k === 'symbol' && d.value.name && d.value.name.charCodeAt(0) !== 91)) d.value = named(d.value, label);
      if (typeof d.get === 'function') d.get = named(d.get, 'get ' + label);
      if (typeof d.set === 'function') d.set = named(d.set, 'set ' + label);
      Object.defineProperty(I.prototype, k, d);
    }
    Object.setPrototypeOf(proto, I.prototype);
    for (const k of Reflect.ownKeys(proto)) {
      if (k !== '__ptLinked') delete proto[k];
    }
    return I.prototype;
  };
  const __nodeListProto = {
    get [Symbol.toStringTag]() { return 'NodeList'; },
    // `length` у браузера на прототипе: собственные свойства списка — индексы
    // и только они, и это видно первым же getOwnPropertyNames.
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    forEach(fn, thisArg) { for (let i = 0; i < this.length; i++) fn.call(thisArg, this[i], i, this); },
    *entries() { for (let i = 0; i < this.length; i++) yield [i, this[i]]; },
    *keys() { for (let i = 0; i < this.length; i++) yield i; },
    *values() { for (let i = 0; i < this.length; i++) yield this[i]; },
    [Symbol.iterator]() { return this.values(); },
  };

  const __collectionProto = {
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    namedItem(n) {
      for (let i = 0; i < this.length; i++) {
        const e = this[i];
        if (e && (e.id === n || (e.getAttribute && __ptGetA(e, 'name') === n))) return e;
      }
      return null;
    },
  };  // Как у Chrome: метка типа — данные, перебор — Array.prototype.values, оба неперечислимы.
  Object.defineProperty(__collectionProto, Symbol.toStringTag, { value: 'HTMLCollection', configurable: true });
  Object.defineProperty(__collectionProto, Symbol.iterator, { value: Array.prototype.values, writable: true, configurable: true });


  // `document.all` — HTMLAllCollection: те же члены, что у HTMLCollection, но
  // на своём интерфейсе. Раньше коллекция строилась как HTMLCollection, а
  // потом ей подменяли прототип — и `length` с `item` терялись: страница
  // читала `document.all.length` и получала undefined.
  const __allProto = {
    get length() { return this.__ptLen | 0; },
    item(i) {
      if (i === undefined) return null;
      const n = String(i);
      if (/^\d+$/.test(n)) return this[+n] != null ? this[+n] : null;
      return this.namedItem(n);
    },
    namedItem(n) {
      const found = [];
      for (let i = 0; i < this.length; i++) {
        const e = this[i];
        if (e && (e.id === n || (e.getAttribute && __ptGetA(e, 'name') === n))) found.push(e);
      }
      if (!found.length) return null;
      return found.length === 1 ? found[0] : __collection(found);
    },
  };  // Как у Chrome: метка типа — данные, перебор — Array.prototype.values, оба неперечислимы.
  Object.defineProperty(__allProto, Symbol.toStringTag, { value: 'HTMLAllCollection', configurable: true });
  Object.defineProperty(__allProto, Symbol.iterator, { value: Array.prototype.values, writable: true, configurable: true });

  function __allCollection(arr) {
    const list = Object.create(__link('HTMLAllCollection', __allProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }

  // `el.attributes` — NamedNodeMap из Attr, а не массив объектов: сборщик
  // отпечатка читает и `Object.prototype.toString`, и цепочку прототипов, и
  // массив там виден сразу.
  const __attrProto = {
    get [Symbol.toStringTag]() { return 'Attr'; },
    get localName() { return this.__ptName; },
    get name() { return this.__ptName; },
    get nodeName() { return this.__ptName; },
    get value() { return this.__ptValue; },
    get nodeValue() { return this.__ptValue; },
    get textContent() { return this.__ptValue; },
    get namespaceURI() { return null; },
    get prefix() { return null; },
    get specified() { return true; },
    get ownerElement() { return this.__ptOwner; },
  };
  function __attr(el, name, value) {
    const a = Object.create(__link('Attr', __attrProto));
    Object.defineProperty(a, '__ptName', { value: name });
    Object.defineProperty(a, '__ptValue', { value: value });
    Object.defineProperty(a, '__ptOwner', { value: el });
    return a;
  }
  const __namedNodeMapProto = {
    get [Symbol.toStringTag]() { return 'NamedNodeMap'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    getNamedItem(n) { const k = String(n).toLowerCase();
      for (let i = 0; i < this.length; i++) if (this[i].name === k) return this[i];
      return null; },
    getNamedItemNS(_ns, n) { return this.getNamedItem(n); },
    setNamedItem(a) { if (a && this.__ptOwner) __ptSetA(this.__ptOwner, a.name, a.value); return null; },
    setNamedItemNS(a) { return this.setNamedItem(a); },
    removeNamedItem(n) { const a = this.getNamedItem(n);
      if (!a) throw new Error("Failed to execute 'removeNamedItem' on 'NamedNodeMap': No item with name '" + n + "' was found.");
      __ptDelA(this.__ptOwner, a.name); return a; },
    removeNamedItemNS(_ns, n) { return this.removeNamedItem(n); },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __namedNodeMap(el) {
    const map = Object.create(__link('NamedNodeMap', __namedNodeMapProto));
    let i = 0;
    for (const [name, value] of el.__ptAttrs) map[i++] = __attr(el, name, value);
    Object.defineProperty(map, '__ptLen', { value: i, enumerable: false, configurable: true });
    Object.defineProperty(map, '__ptOwner', { value: el });
    return map;
  }

  // `classList` — DOMTokenList: живой, пишет обратно в атрибут, и это интерфейс,
  // а не литерал с методами.
  const __tokenListProto = {
    get [Symbol.toStringTag]() { return 'DOMTokenList'; },
    get value() { return __ptGetA(this.__ptEl, 'class') || ''; },
    set value(v) { __ptSetA(this.__ptEl, 'class', String(v)); },
    get length() { return this.__ptTokens().length; },
    item(i) { const t = this.__ptTokens(); return i >= 0 && i < t.length ? t[i] : null; },
    contains(c) { return this.__ptTokens().includes(String(c)); },
    add(...cs) { const t = this.__ptTokens();
      for (const c of cs) if (!t.includes(String(c))) t.push(String(c));
      __ptSetA(this.__ptEl, 'class', t.join(' ')); },
    remove(...cs) { const drop = cs.map(String);
      __ptSetA(this.__ptEl, 'class', this.__ptTokens().filter((c) => !drop.includes(c)).join(' ')); },
    toggle(c, force) { const t = this.__ptTokens(), has = t.includes(String(c));
      if (force === true || (force === undefined && !has)) {
        if (!has) t.push(String(c));
        __ptSetA(this.__ptEl, 'class', t.join(' '));
        return true;
      }
      __ptSetA(this.__ptEl, 'class', t.filter((x) => x !== String(c)).join(' '));
      return false; },
    replace(from, to) { const t = this.__ptTokens(), i = t.indexOf(String(from));
      if (i < 0) return false;
      t[i] = String(to); __ptSetA(this.__ptEl, 'class', t.join(' ')); return true; },
    supports() { throw new TypeError("Failed to execute 'supports' on 'DOMTokenList': DOMTokenList has no supported tokens."); },
    forEach(fn, thisArg) { this.__ptTokens().forEach((v, i) => fn.call(thisArg, v, i, this)); },
    *entries() { const t = this.__ptTokens(); for (let i = 0; i < t.length; i++) yield [i, t[i]]; },
    *keys() { const t = this.__ptTokens(); for (let i = 0; i < t.length; i++) yield i; },
    *values() { yield* this.__ptTokens(); },
    [Symbol.iterator]() { return this.values(); },
    toString() { return this.value; },
  };
  function __tokenList(el) {
    const proto = __link('DOMTokenList', __tokenListProto);
    let list = el.__ptTokenList;
    if (!list) {
      list = Object.create(proto);
      Object.defineProperty(list, '__ptEl', { value: el });
      Object.defineProperty(list, '__ptTokens', {
        value: () => (__ptGetA(el, 'class') || '').split(/\s+/).filter(Boolean),
      });
      Object.defineProperty(el, '__ptTokenList', { value: list, enumerable: false, writable: true });
    }
    // Индексы — собственные свойства, как у браузера: `list[0]` работает.
    const t = list.__ptTokens(), prev = list.__ptCount | 0;
    for (let i = 0; i < t.length; i++) list[i] = t[i];
    for (let i = t.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, '__ptCount', { value: t.length, configurable: true });
    return list;
  }

  // ---- Node -----------------------------------------------------------------
  class Node {
    constructor(type) {
      // Backing fields are __pt-prefixed (and therefore filtered out of every
      // introspection route by the stealth layer); the standard names are
      // prototype accessors defined below. A real DOM node has *no* own
      // properties — `Object.getOwnPropertyNames(document.body)` is `[]` — so
      // storing these directly on the instance would be an instant tell.
      this.__ptType = type;
      this.__ptKids = [];
      this.__ptParent = null;
      this.__ptDoc = globalThis.document || null;
      this.__ptLis = Object.create(null);
    }
    get firstChild() { return this.__ptKids[0] || null; }
    get lastChild() { return this.__ptKids[this.__ptKids.length - 1] || null; }
    get nextSibling() {
      const p = this.parentNode; if (!p) return null;
      const i = p.__ptKids.indexOf(this); return p.__ptKids[i + 1] || null;
    }
    get previousSibling() {
      const p = this.parentNode; if (!p) return null;
      const i = p.__ptKids.indexOf(this); return p.__ptKids[i - 1] || null;
    }
    hasChildNodes() { return this.__ptKids.length > 0; }
    contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; }
    // Walks out through a shadow host too: a node inside an attached shadow tree
    // is connected, even though the root itself has no parent.
    // Базовый адрес — у документа: у `about:blank` он от создателя.
    get baseURI() {
      const d = this.nodeType === 9 ? this : (this.ownerDocument || null);
      return d && typeof d.__ptBaseURI === 'function' ? d.__ptBaseURI() : ((globalThis.location && globalThis.location.href) || 'about:blank');
    }
    get isConnected() {
      for (let n = this; n; n = n.parentNode || n.__ptHost) {
        if (n.nodeType === DOCUMENT_NODE) return true;
      }
      return false;
    }
    getRootNode(opts) {
      let n = this;
      while (n.parentNode || (n.__ptHost && opts && opts.composed)) n = n.parentNode || n.__ptHost;
      return n;
    }

    appendChild(child) {
      __needArgs(arguments.length, 1, 'appendChild', 'Node');
      __needNode(child, 1, 'appendChild');
      // Узел не может содержать сам себя — и своего предка тоже.
      for (let p = this; p; p = p.parentNode) {
        if (p === child) {
          throw new (globalThis.DOMException || Error)(
            "Failed to execute 'appendChild' on 'Node': The new child element contains the parent.",
            'HierarchyRequestError');
        }
      }
      return __ptInsert.call(this, child, null);
    }
    insertBefore(child, ref) {
      __needArgs(arguments.length, 2, 'insertBefore', 'Node');
      __needNode(child, 1, 'insertBefore');
      // Второй параметр у браузера — `Node?`: `undefined` для него та же
      // пустота, что и `null`, и означает «в конец».
      if (ref !== null && ref !== undefined) {
        __needNode(ref, 2, 'insertBefore');
        __needChild(this, ref, 'insertBefore',
          'The node before which the new node is to be inserted is not a child of this node.');
      }
      if (child.nodeType === DOCUMENT_FRAGMENT_NODE) {
        for (const c of child.__ptKids.slice()) this.insertBefore(c, ref);
        return child;
      }
      if (child.parentNode) __ptDrop.call(child.parentNode, child);
      // Узел из другого документа усыновляется: ownerDocument у него и у всего
      // поддерева становится документом нового родителя, как в браузере.
      try {
        const doc = this.nodeType === 9 ? this : this.__ptDoc;
        if (doc && child.__ptDoc !== doc) __walkTree(child, (n) => { if (n.__ptDoc !== doc) n.__ptDoc = doc; });
      } catch (e) {}
      const i = (ref === null || ref === undefined) ? -1 : this.__ptKids.indexOf(ref);
      if (i < 0) this.__ptKids.push(child); else this.__ptKids.splice(i, 0, child);
      child.__ptParent = this;
      __markDirty();
      __mutation(__childListRecord(this, [child], [], child.previousSibling, child.nextSibling));
      // A frame only becomes a browsing context once it is in the document — and
      // the frame is rarely the node being inserted. A widget builds its tree
      // detached and inserts the root of it: Turnstile puts its iframe in a closed
      // shadow root and then connects the host, so checking only `child` left the
      // iframe sitting there, connected and inert, and the widget waiting forever
      // for a frame that never opened.
      if (child.isConnected) __connectSubtree(child);
      return child;
    }
    removeChild(child) {
      __needArgs(arguments.length, 1, 'removeChild', 'Node');
      __needNode(child, 1, 'removeChild');
      const i = this.__ptKids.indexOf(child);
      if (i < 0) {
        throw new (globalThis.DOMException || Error)(
          "Failed to execute 'removeChild' on 'Node': The node to be removed is not a child of this node.",
          'NotFoundError');
      }
      const prev = this.__ptKids[i - 1] || null, next = this.__ptKids[i + 1] || null;
      this.__ptKids.splice(i, 1); child.__ptParent = null; __markDirty();
      __mutation(__childListRecord(this, [], [child], prev, next));
      // A removed frame is a closed browsing context. Without this its V8 context
      // outlives the element forever — a widget that replaces its iframe on a
      // retry (Turnstile does, repeatedly) would pile them up until the cap. The
      // whole subtree goes, for the same reason it connects as a whole.
      __walkTree(child, (f) => {
        if (f.__ptFrameId) __ptDisconnectFrame(f);
        // Кадр с песочницей: его окно остаётся у страницы в руках, но контекст
        // закрыт — размеры нулевые, `closed`, без `frameElement`.
        if (f.__ptRealm) { try { if (typeof f.__ptRealm.__pt_detach === 'function') f.__ptRealm.__pt_detach(); } catch (e) {} try { __realmFrames.delete(f); } catch (e) {} }
        if (f.__ptUpgraded) __customCallback(f, 'disconnectedCallback');
      });
      return child;
    }
    replaceChild(nw, old) {
      __needArgs(arguments.length, 2, 'replaceChild', 'Node');
      __needNode(nw, 1, 'replaceChild');
      __needNode(old, 2, 'replaceChild');
      __needChild(this, old, 'replaceChild',
        'The node to be replaced is not a child of this node.');
      this.insertBefore(nw, old);
      return this.removeChild(old);
    }
    cloneNode(deep) {
      const c = this.__ptShallowClone();
      // Копия несёт точные числа инлайнового стиля, а не напечатанные
      // шестью знаками: браузер клонирует разобранное объявление, и
      // `scale(1.000998)` у копии остаётся 1.000998, хотя в атрибуте 1.001.
      try {
        if (this.__ptStyle && c.style) {
          const sr = __declRaw.get(this.__ptStyle), sm = sr && sr();
          if (sm && sm.__ptPrecise && sm.__ptPrecise.size) {
            const dr = __declRaw.get(c.style), dm = dr && dr();
            if (dm) { const pm = __cssPrecise(dm); for (const [k, v] of sm.__ptPrecise) if (dm.has(k)) pm.set(k, v); }
          }
        }
      } catch (e) {}
      if (deep) for (const ch of this.__ptKids) c.appendChild(ch.cloneNode(true));
      if (deep && this.__ptLocal === 'template' && this.__ptContent) {
        const into = __templateContent(c);
        for (const ch of this.__ptContent.__ptKids) into.appendChild(ch.cloneNode(true));
      }
      return c;
    }

    get textContent() {
      // У документа и doctype его нет вовсе — браузер отвечает null, а не
      // склеенным текстом страницы.
      if (this.nodeType === 9 || this.nodeType === 10) return null;
      // Текст, комментарий, инструкция — их данные (у Chrome это Node.textContent).
      if (this.nodeType === 3 || this.nodeType === 4 || this.nodeType === 7) return this.data;
      if (this.nodeType === 8) return this.data;
      let s = ''; for (const c of this.__ptKids) s += c.textContent; return s;
    }
    set textContent(v) {
      if (this.nodeType === 9 || this.nodeType === 10) return;
      if (this.nodeType === 3 || this.nodeType === 4 || this.nodeType === 7 || this.nodeType === 8) { this.data = String(v); return; }
      this.__ptKids = [];
      if (v !== '') __ptAdd.call(this, new Text(String(v)));
    }

    // EventTarget
    addEventListener(type, fn, opts) {
      __needArgs(arguments.length, 2, 'addEventListener', 'EventTarget');
      if (!fn) return;
      const cap = !!(opts && (opts === true || opts.capture));
      // Обработчик-свойство встаёт в очередь там, где его присвоили: если
      // `onload` был задан раньше первого слушателя, браузер зовёт его первым.
      // Присваивание нам не перехватить — `on…` у элемента обычное свойство, —
      // но здесь видно, было ли оно уже занято.
      if (!this.__ptOnFirst) {
        Object.defineProperty(this, '__ptOnFirst', { value: {}, enumerable: false, configurable: true });
      }
      if (this.__ptOnFirst[type] === undefined) {
        this.__ptOnFirst[type] = typeof this['on' + type] === 'function';
      }
      (this.__ptLis[type] || (this.__ptLis[type] = [])).push({ fn, cap });
    }
    removeEventListener(type, fn, opts) {
      const cap = !!(opts && (opts === true || opts.capture));
      const l = this.__ptLis[type]; if (!l) return;
      this.__ptLis[type] = l.filter(e => !(e.fn === fn && e.cap === cap));
    }
    __ptDispatch(event) {
      __ptEvSet(event, 'target', this);
      // `window.event` — событие, которое обрабатывается прямо сейчас. Старое,
      // но живое свойство: у нас оно было `undefined` всегда, а в Chrome внутри
      // обработчика там лежит само событие.
      const снимок = __ptTakeEvent(event);
      // Путь события, как в браузере: вверх по parentNode, из теневого дерева —
      // через хозяина (для composed), от документа — к окну (кроме load).
      // Для узлов снаружи тени цель подменяется хозяином. Раньше путь кончался
      // на корне тени и никогда не доходил до окна: слушатели мыши на window и
      // document у виджета не слышали ни одного нашего движения.
      const path = [], targets = [];
      let tgt = this;
      // enter/leave у Chrome слушатели предков (и окна) не слышат вовсе.
      const local = event.type === 'mouseenter' || event.type === 'mouseleave' || event.type === 'pointerenter' || event.type === 'pointerleave';
      for (let n = this; n; ) {
        if (local && n !== this) break;
        path.push(n); targets.push(tgt);
        if (n.nodeType === 11 && n.host) {
          if (!event.composed) break;
          n = n.host; tgt = n; continue;
        }
        if (n.nodeType === 9) {
          const w = n.defaultView;
          if (w && event.type !== 'load') { path.push(w); targets.push(tgt); }
          break;
        }
        n = n.parentNode;
      }
      __ptEvSet(event, '__ptPathNow', path);
      const fireAt = (i, phase) => {
        const node = path[i];
        const l = node.__ptLis && node.__ptLis[event.type];
        __ptEvSet(event, 'target', targets[i]);
        // Хозяин тени после подмены цели сам и есть цель: фаза «у цели».
        __ptEvSet(event, 'eventPhase', targets[i] === node ? 2 : phase);
        if (l) {
          for (const e of l.slice()) {
            if (event.__ptStopImm) break;
            if (phase === 1 && !e.cap) continue;
            if (phase === 3 && e.cap) continue;
            __ptEvSet(event, 'currentTarget', node);
            try { e.fn.call(node, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
          }
        }
        // Обработчик-свойство предка (`document.onmousemove`, `window.onclick`)
        // — тоже слушатель всплытия.
        if (phase === 3 && !event.__ptStopImm) {
          let on; try { on = node['on' + event.type]; } catch (x) {}
          if (typeof on === 'function') {
            __ptEvSet(event, 'currentTarget', node);
            try { on.call(node, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
          }
        }
      };
      for (let i = path.length - 1; i >= 1; i--) { if (event.__ptStop) break; fireAt(i, 1); }
      __ptEvSet(event, 'target', this);
      __ptEvSet(event, 'eventPhase', 2);
      // Обработчик-свойство (`onclick`, `onload`, `onmessage`) — такой же
      // слушатель цели, и вызывает его тот же dispatch, а не вызывающий код.
      // Порядок — тот, в котором его завели: раньше слушателей или позже.
      const onFirst = !!(this.__ptOnFirst && this.__ptOnFirst[event.type]);
      const callOn = () => {
        if (event.__ptStopImm) return;
        const on = this['on' + event.type];
        if (typeof on === 'function') {
          __ptEvSet(event, 'currentTarget', this);
          try { on.call(this, event); } catch (e) { __pt_reportError(e, 'listener ' + event.type); }
        }
      };
      // У цели — сначала слушатели захвата, потом остальные (Chrome ≥ 89).
      const atTarget = (capture) => {
        const l = this.__ptLis && this.__ptLis[event.type]; if (!l) return;
        for (const e of l.slice()) {
          if (event.__ptStopImm) break;
          if (!!e.cap !== capture) continue;
          __ptEvSet(event, 'currentTarget', this);
          try { e.fn.call(this, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
        }
      };
      if (!event.__ptStop) atTarget(true);
      if (!event.__ptStop && onFirst) callOn();
      if (!event.__ptStop) atTarget(false);
      if (!onFirst) callOn();
      if (event.bubbles) for (let i = 1; i < path.length; i++) { if (event.__ptStop) break; fireAt(i, 3); }
      __ptEvSet(event, 'eventPhase', 0);
      __ptEvSet(event, 'currentTarget', null);
      // Снаружи после рассылки видна цель со стороны документа (хозяин тени).
      __ptEvSet(event, 'target', targets[targets.length - 1]);
      __ptEvSet(event, '__ptPathNow', null);
      // Возвращаем `window.event` как было: вне обработки его нет.
      __ptDropEvent(снимок);
      return !event.defaultPrevented;
    }
  }
  // Исключение из обработчика в браузере не пропадает: оно уходит в
  // `window.onerror`, поднимает событие `error` на окне и печатается в консоль.
  // Мы его молча глотали — из-за чего страница, у которой обработчик падает,
  // выглядела как страница, которая просто чего-то ждёт.
  globalThis.__pt_reportError = (e, where) => {
    const msg = 'Uncaught ' + String((e && e.name ? e.name + ': ' + e.message : e));
    try {
      const on = globalThis.onerror;
      if (typeof on === 'function') {
        on.call(globalThis, msg, (e && e.fileName) || (globalThis.location && location.href) || '',
                (e && e.lineNumber) || 0, (e && e.columnNumber) || 0, e);
      }
    } catch (x) {}
    try {
      if (globalThis.ErrorEvent && globalThis.dispatchEvent) {
        const ev = new ErrorEvent('error', { message: msg, error: e });
        globalThis.dispatchEvent(ev);
      }
    } catch (x) {}
    try { console.error(msg + (where ? ' (' + where + ')' : ''), (e && e.stack) || ''); } catch (x) {}
  };

  function fireCapture(node, event) {
    const l = node.__ptLis && node.__ptLis[event.type]; if (!l) return;
    for (const e of l.slice()) { if (!e.cap) continue; if (event.__ptStopImm) break; __ptEvSet(event, 'currentTarget', node); try { e.fn.call(node, event); } catch (x) { __pt_reportError(x, 'capture ' + event.type); } }
  }

  // В браузере эти три метода живут на `EventTarget.prototype` — один раз, для
  // всех целей, и они же разносят событие по дереву, когда цель в дереве. У нас
  // они стояли на `Node.prototype` (лишние имена там, где браузер их не держит)
  // плюс отдельная копия на EventTarget. Теперь реализация одна, а имена — там,
  // где им положено.
  {
    const ET = globalThis.EventTarget;
    if (ET && ET.prototype) {
      const store = (t) => {
        if (!t.__ptLis) {
          try { Object.defineProperty(t, '__ptLis', { value: Object.create(null), enumerable: false, writable: true }); }
          catch (e) { return Object.create(null); }
        }
        return t.__ptLis;
      };
      // Без получателя цель — окно: голый `addEventListener(...)` даёт
      // `this === undefined`, и браузер подставляет глобальный объект.
      const self_ = (t) => (t === undefined || t === null ? globalThis : t);
      const proto = ET.prototype;
      for (const [name, fn] of [
        ['addEventListener', function addEventListener(type, fn, opts) {
          __needArgs(arguments.length, 2, 'addEventListener', 'EventTarget');
          const t = self_(this); if (!fn) return;
          const cap = !!(opts && (opts === true || opts.capture));
          // Тот же учёт порядка, что и у узла: был ли `on…` занят раньше
          // первого слушателя. Присваивание не перехватить — здесь видно.
          try {
            if (!t.__ptOnFirst) {
              Object.defineProperty(t, '__ptOnFirst', { value: {}, enumerable: false, configurable: true });
            }
            if (t.__ptOnFirst[type] === undefined) {
              t.__ptOnFirst[type] = typeof t['on' + type] === 'function';
            }
          } catch (e) {}
          const l = store(t); (l[type] = l[type] || []).push({ fn, cap, once: !!(opts && opts.once) });
        }],
        ['removeEventListener', function removeEventListener(type, fn, opts) {
          __needArgs(arguments.length, 2, 'removeEventListener', 'EventTarget');
          const t = self_(this);
          const cap = !!(opts && (opts === true || opts.capture));
          const l = t.__ptLis && t.__ptLis[type]; if (!l) return;
          t.__ptLis[type] = l.filter((e) => !(e.fn === fn && e.cap === cap));
        }],
        ['dispatchEvent', function dispatchEvent(event) {
          const t = self_(this);
          return Node.prototype.__ptDispatch.call(t, event);
        }],
      ]) {
        try {
          Object.defineProperty(proto, name, { value: globalThis.__pt_native ? __pt_native(fn) : fn,
                                               writable: true, enumerable: true, configurable: true });
        } catch (e) {}
      }
      // Узел наследует их оттуда же, откуда и браузерный.
      try { Object.setPrototypeOf(Node.prototype, proto); } catch (e) {}
      for (const name of ['addEventListener', 'removeEventListener', 'dispatchEvent']) {
        try { delete Node.prototype[name]; } catch (e) {}
      }
    }
  }

  // Expose the standard node properties as prototype accessors over the hidden
  // backing fields, so instances stay free of own properties (see constructor).
  const accessor = (name, get, set) => {
    // Real accessors report `function get <name>() { [native code] }`; an
    // anonymous function would read `function ()` and stand out.
    try { Object.defineProperty(get, 'name', { value: 'get ' + name, configurable: true }); } catch (e) {}
    try { Object.defineProperty(set, 'name', { value: 'set ' + name, configurable: true }); } catch (e) {}
    return { get, set, configurable: true, enumerable: false };
  };
  // Имена кодировок Chrome отдаёт каноническими: utf-8 → UTF-8, latin1 →
  // windows-1252. Прочие проходят как есть, в нижнем регистре.
  const __ENCODINGS = {
    'utf-8': 'UTF-8', 'utf8': 'UTF-8', 'unicode-1-1-utf-8': 'UTF-8',
    'iso-8859-1': 'windows-1252', 'latin1': 'windows-1252', 'ascii': 'windows-1252',
    'us-ascii': 'windows-1252', 'windows-1252': 'windows-1252', 'cp1252': 'windows-1252',
    'utf-16': 'UTF-16LE', 'utf-16le': 'UTF-16LE', 'utf-16be': 'UTF-16BE',
  };
  const __normEncoding = (name) => {
    const k = String(name).trim().toLowerCase();
    return __ENCODINGS[k] || k;
  };

  // ChildNode.remove живёт на элементах и текстовых узлах — у документа его нет,
  // и лишнее имя на `document` заметно ровно так же, как недостающее.
  // Событие движок метит сам: цель, текущую цель и стадию у браузера читают,
  // но не пишут, и установщиков у них нет. Свои события держат это в `__ptE`,
  // а пришедшие с другого этажа — собственным свойством.
  // `window.event` — событие, которое обрабатывается прямо сейчас. У воркера
  // такого имени нет вовсе, и восстановление «как было» не должно его
  // заводить: присваивание `undefined` создаёт собственное свойство, и в
  // воркере появлялось лишнее имя, которого у браузера там нет.
  // Признак окна — не `document` (движок строит его и в воркере, просто
  // прячет), а `importScripts`: он есть только у воркера.
  const __ptEventSlot = () => typeof importScripts === 'undefined';
  const __ptTakeEvent = (ev) => {
    const было = Object.prototype.hasOwnProperty.call(globalThis, 'event');
    const прежнее = было ? globalThis.event : undefined;
    if (__ptEventSlot()) { try { globalThis.event = ev; } catch (e) {} }
    return { было, прежнее };
  };
  const __ptDropEvent = (снимок) => {
    try {
      if (снимок.было) globalThis.event = снимок.прежнее;
      else delete globalThis.event;
    } catch (e) {}
  };

  // Событие фокуса: у браузера это `FocusEvent` со вторым участником и с
  // доверием — его шлёт он сам, даже когда фокус попросили из скрипта.
  const __ptFocusEvent = (type, related, bubbles) => {
    const C = globalThis.FocusEvent || globalThis.Event;
    let ev;
    // focus/blur/focusin/focusout у браузера composed — проходят сквозь тень.
    try { ev = new C(type, { bubbles: !!bubbles, cancelable: false, composed: true, relatedTarget: related || null }); }
    catch (e) { ev = new Event(type, { bubbles: !!bubbles }); }
    if (!('relatedTarget' in ev)) {
      try { Object.defineProperty(ev, 'relatedTarget', { value: related || null, enumerable: true, configurable: true }); }
      catch (e) {}
    }
    // Фокус от нажатия мыши несёт устройство ввода, как у Chrome.
    if (globalThis.__ptFocusCaps && ev.__ptE) ev.__ptE.sourceCapabilities = globalThis.__ptFocusCaps;
    return __ptTrust(ev);
  };

  const __ptEvSet = (ev, key, value) => {
    if (!ev) return;
    if (ev.__ptE) { ev.__ptE[key] = value; return; }
    try { Object.defineProperty(ev, key, { value, configurable: true, writable: true }); } catch (e) {}
  };

  const __removeSelf = function remove() { if (this.parentNode) this.parentNode.removeChild(this); };

  Object.defineProperties(Node.prototype, {
    nodeType: accessor('nodeType', function () { return this.__ptType; }, function (v) { this.__ptType = v; }),
    childNodes: accessor('childNodes',
      function () { return __nodeList(this); },
      function (v) { this.__ptKids = Array.from(v); }),
    parentNode: accessor('parentNode', function () { return this.__ptParent; }, function (v) { this.__ptParent = v; }),
    ownerDocument: accessor('ownerDocument', function () { return this.__ptDoc; }, function (v) { this.__ptDoc = v; }),
  });

  // ---- CharacterData: Text / Comment ---------------------------------------
  class Text extends Node {
    constructor(data) { super(TEXT_NODE); this.__ptData = String(data); }
    get data() { return this.__ptData; }
    set data(v) { this.__ptData = String(v); }
    get nodeName() { return '#text'; }
    get nodeValue() { return this.data; }
    set nodeValue(v) { this.data = String(v); }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
    get length() { return this.data.length; }
    __ptShallowClone() { return new Text(this.data); }
  }
  class Comment extends Node {
    constructor(data) { super(COMMENT_NODE); this.__ptData = String(data); }
    get data() { return this.__ptData; }
    set data(v) { this.__ptData = String(v); }
    get nodeName() { return '#comment'; }
    get nodeValue() { return this.data; }
    get textContent() { return this.data; }
    get length() { return this.data.length; }
    __ptShallowClone() { return new Comment(this.data); }
  }

  // ---- Element --------------------------------------------------------------
  /// A shadow root: a fragment that carries the query surface of an element and
  /// remembers its host, so a subtree can live outside the document tree while
  /// still being connected through it.
  // DocumentFragment — свой интерфейс, а не псевдоним Node: у браузера на нём
  // ровно одиннадцать членов, и `t.content.querySelector(...)` работает именно
  // благодаря им. У нас фрагмент был голым Node, и запрос по нему падал.
  class DocumentFragment extends Node {
    constructor() { super(DOCUMENT_FRAGMENT_NODE); }
    get [Symbol.toStringTag]() { return 'DocumentFragment'; }
    // Обрывок тоже копируется: без этого `cloneNode` на нём падал, а через
    // него ходят `importNode` и содержимое `<template>`.
    __ptShallowClone() { const f = new DocumentFragment(); f.__ptDoc = this.ownerDocument; return f; }
    get children() { return __collection(this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.nodeType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE);
      return k.length ? k[k.length - 1] : null;
    }
    getElementById(id) { return firstMatch(this, (e) => __ptGetA(e, 'id') === String(id)); }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return query(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'))[0] || null;
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...nodes) {
      const first = this.__ptKids[0] || null;
      for (const n of nodes) this.insertBefore(typeof n === 'string' ? new Text(n) : n, first);
    }
    replaceChildren(...nodes) {
      this.__ptKids = [];
      for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    moveBefore(node, child) { return this.insertBefore(node, child); }
  }

  class ShadowRoot extends DocumentFragment {
    constructor(host, mode) {
      super();
      this.__ptHost = host;
      this.__ptMode = mode;
      this.__ptDoc = host.ownerDocument;
    }
    get [Symbol.toStringTag]() { return 'ShadowRoot'; }
    get host() { return this.__ptHost; }
    get mode() { return this.__ptMode; }
    get delegatesFocus() { return !!this.__ptDelegatesFocus; }
    get clonable() { return !!this.__ptClonable; }
    get serializable() { return !!this.__ptSerializable; }
    get slotAssignment() { return this.__ptSlotAssignment || 'named'; }
    getHTML(opts) { return this.__ptKids.map((n) => serializeNode(n, !!(opts && opts.serializableShadowRoots))).join(''); }
    get nodeName() { return '#document-fragment'; }
    get nodeValue() { return null; }
    get textContent() { return this.__ptKids.map(n => n.textContent).join(''); }
    set textContent(v) { this.__ptKids = []; if (v !== '') this.appendChild(new Text(String(v))); }
    get innerHTML() {
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      return host.__ptKids.map(serializeNode).join('');
    }
    set innerHTML(html) {
      // Разметка шаблона разбирается в его содержимое — таков разбор у него.
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      host.__ptKids = [];
      for (const n of parseFragment(String(html))) __ptAdd.call(host, n);
    }
    // Коллекция, а не массив: `document.children` у браузера — HTMLCollection,
    // и `Object.prototype.toString` на нём отвечает именно так.
    get children() { return __collection(this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE)); }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get childElementCount() { return this.children.length; }
    // В браузере это `<body>`, как только тело есть, — не null. И это
    // свойство присваивают (`focus()`), так что одного геттера мало:
    // присваивание в него молча пропадало.
    get activeElement() { return this.__ptActive || this.body || null; }
    set activeElement(v) { this.__ptActive = v; }
    // Список таблиц стилей — не массив: у браузера это `StyleSheetList`, и
    // `Array.isArray(sr.styleSheets)` там ложно. Мы отдавали литерал массива, а
    // виджет живёт как раз в теневом корне и читает его оттуда.
    get styleSheets() { return __styleSheetList(__sheetOwners(this)); }
    get adoptedStyleSheets() { return this.__ptAdopted || (this.__ptAdopted = []); }
    set adoptedStyleSheets(v) { this.__ptAdopted = v; }
    getElementById(id) { return firstMatch(this, e => e.id === id); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) {
      const cs = String(c).split(/\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = (e.__ptAttrs.get('class') || '').split(/\s+/);
        return cs.every((x) => own.indexOf(x) >= 0);
      }));
    }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return query(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'))[0] || null;
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }
    // DocumentOrShadowRoot: у теневого корня — те же ответы, что у документа
    // (Chrome отдаёт стопку до <html>), а не пустота.
    elementFromPoint(x, y) { const d = globalThis.document; return d ? d.elementFromPoint(x, y) : null; }
    elementsFromPoint(x, y) { const d = globalThis.document; return d ? d.elementsFromPoint(x, y) : []; }
    getSelection() { return typeof globalThis.getSelection === 'function' ? globalThis.getSelection() : null; }
    getAnimations() { return []; }
  }

  // --- пользовательские элементы -------------------------------------------
  // `customElements` был объектом без методов: `customElements.get` роняло любой
  // бандл, который просто спрашивает, определён ли компонент. Реестр настоящий:
  // определение, обновление уже стоящих в документе узлов и три обратных вызова
  // жизненного цикла.
  const __customs = new Map();          // имя → класс
  const __customPending = new Map();    // имя → { promise, resolve }
  const __customName = (ctor) => {
    for (const [name, C] of __customs) if (C === ctor) return name;
    return null;
  };
  const __customCallback = (el, name, args) => {
    const fn = el[name];
    if (typeof fn === 'function') { try { fn.apply(el, args || []); } catch (e) { /* компонент бросил */ } }
  };
  const __customUpgrade = (el, Ctor) => {
    if (el.__ptUpgraded) return;
    Object.defineProperty(el, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
    // Повторно выполнить тело конструктора над готовым узлом нельзя, поэтому
    // элемент получает прототип класса — методы и обратные вызовы на месте.
    try { Object.setPrototypeOf(el, Ctor.prototype); } catch (e) { return; }
    const watched = Ctor.observedAttributes;
    if (Array.isArray(watched)) {
      for (const a of watched) {
        const v = __ptGetA(el, a);
        if (v !== null) __customCallback(el, 'attributeChangedCallback', [a, null, v, null]);
      }
    }
    if (el.isConnected) __customCallback(el, 'connectedCallback');
  };

  class CustomElementRegistry {
    define(name, ctor, options) {
      name = String(name);
      if (!/^[a-z][a-z0-9._]*-[a-z0-9._-]*$/.test(name)) {
        throw new (globalThis.DOMException || Error)(`"${name}" is not a valid custom element name`, 'SyntaxError');
      }
      if (__customs.has(name)) {
        throw new (globalThis.DOMException || Error)(`"${name}" has already been defined`, 'NotSupportedError');
      }
      if (typeof ctor !== 'function') throw new TypeError('constructor is not a constructor');
      __customs.set(name, ctor);
      const doc = globalThis.document;
      if (doc && doc.documentElement) {
        for (const el of __docTags(doc, name)) __customUpgrade(el, ctor);
      }
      const pending = __customPending.get(name);
      if (pending) { pending.resolve(ctor); __customPending.delete(name); }
    }
    get(name) { return __customs.get(String(name)); }
    getName(ctor) { return __customName(ctor); }
    whenDefined(name) {
      name = String(name);
      const known = __customs.get(name);
      if (known) return Promise.resolve(known);
      let entry = __customPending.get(name);
      if (!entry) {
        let resolve;
        const promise = new Promise((r) => { resolve = r; });
        entry = { promise, resolve };
        __customPending.set(name, entry);
      }
      return entry.promise;
    }
    upgrade(root) {
      __walkTree(root, (el) => {
        if (el.nodeType !== ELEMENT_NODE) return;
        const C = __customs.get(el.__ptLocal);
        if (C) __customUpgrade(el, C);
      });
    }
  }

  class Element extends Node {
    constructor(tag) {
      super(ELEMENT_NODE);
      // `new MyElement()` не передаёт имя тега — его знает реестр, по классу,
      // от которого элемент произошёл. Так работает и настоящий HTMLElement.
      if (tag === undefined && new.target) tag = __customName(new.target) || 'unknown';
      this.__ptTag = String(tag).toUpperCase();
      this.__ptLocal = String(tag).toLowerCase();
      this.__ptAttrs = new Map();
    }
    get nodeName() { return this.tagName; }
    get tagName() { return this.__ptTag; }
    get localName() { return this.__ptLocal; }
    // Пространство имён элемента: заглушка таблицы форм отвечала XHTML всем,
    // в том числе SVG из createElementNS.
    get namespaceURI() { return this.__ptNS === undefined ? 'http://www.w3.org/1999/xhtml' : this.__ptNS; }
    get prefix() { return this.__ptPrefix || null; }
    // Объявление стиля строится при первом обращении, а не при создании
    // узла: у него семьсот собственных свойств, и на страницу с тысячей
    // элементов это полсекунды на пустом месте. Браузер создаёт узел за
    // полмикросекунды, у нас выходило полмиллисекунды.
    get style() {
      if (!this.__ptStyle) {
        Object.defineProperty(this, '__ptStyle', {
          value: makeStyle(this), writable: true, enumerable: false, configurable: true,
        });
      }
      return this.__ptStyle;
    }

    // Attributes. Имена в нижний регистр — только у HTML-элементов; у SVG и
    // прочих чужих имена регистрозависимы (`viewBox`), как в спецификации.
    getAttribute(n) { const v = this.__ptAttrs.get(__attrName(this, n)); return v === undefined ? null : v; }
    setAttribute(n, v) {
      __needArgs(arguments.length, 2, 'setAttribute', 'Element');
      const name = __attrName(this, n), old = this.__ptAttrs.get(name);
      this.__ptAttrs.set(name, String(v));
      if (this.__ptUpgraded) {
        const watched = this.constructor && this.constructor.observedAttributes;
        if (Array.isArray(watched) && watched.indexOf(name) >= 0) {
          __customCallback(this, 'attributeChangedCallback',
            [name, old === undefined ? null : old, String(v), null]);
        }
      }
      __markDirty();
      __mutation({ type: 'attributes', target: this, attributeName: name, attributeNamespace: null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    removeAttribute(n) {
      const name = __attrName(this, n), old = this.__ptAttrs.get(name);
      this.__ptAttrs.delete(name);
      __markDirty();
      __mutation({ type: 'attributes', target: this, attributeName: name, attributeNamespace: null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    hasAttribute(n) { return this.__ptAttrs.has(__attrName(this, n)); }
    getAttributeNames() { return [...this.__ptAttrs.keys()]; }
    get attributes() { return __namedNodeMap(this); }

    get id() { return __ptGetA(this, 'id') || ''; }
    set id(v) { __ptSetA(this, 'id', v); }
    get className() { return __ptGetA(this, 'class') || ''; }
    set className(v) { __ptSetA(this, 'class', v); }
    get classList() { return __tokenList(this); }
    get dataset() { return makeDataset(this); }

    // URL-valued attributes reflect as *absolute* URLs, exactly as in a browser.
    // Not cosmetic: Cloudflare's Turnstile finds its own `<script>` by comparing
    // `script.src` against its api.js URL, and while this returned `''` the
    // widget refused to initialise ("Could not find Turnstile valid script tag").
    get src() { return this.__ptUrlAttr('src'); }
    set src(v) {
      __ptSetA(this, 'src', v);
      // Картинка идёт в сеть от одного присваивания, без всякого документа:
      // `new Image().src = …` — обычный способ послать GET, и у нас он не
      // посылал ничего. Запрос делает браузер сам, поэтому мимо страничного
      // `fetch`, а по готовности бросаем `load` или `error`, как он.
      if (this.__ptLocal === 'img') { this.__ptLoadImage(); return; }
      if (!this.isConnected) return;
      // The src can arrive after the element is in the document, in either order:
      // `el.src = …; head.appendChild(el)` or `head.appendChild(el); el.src = …`.
      if (this.__ptConnectFrame) this.__ptConnectFrame();
      if (this.__ptRunScript) this.__ptRunScript();
    }

    __ptLoadImage() {
      const raw = __ptGetA(this, 'src');
      if (!raw) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (this.__ptImgAt === url) return;                 // тот же адрес — не грузим дважды
      Object.defineProperty(this, '__ptImgAt', { value: url, configurable: true, enumerable: false });
      Object.defineProperty(this, '__ptImgDone', { value: false, writable: true, configurable: true, enumerable: false });
      if (url.slice(0, 5) === 'data:' || url.slice(0, 5) === 'blob:') {
        this.__ptImgDone = true;
        // Не картинка (`data:,x`, текстовый blob) — у браузера это `error`.
        let isImage = true;
        try {
          if (url.slice(0, 5) === 'data:') {
            const comma = url.indexOf(',');
            const meta = comma < 0 ? '' : url.slice(5, comma).toLowerCase();
            const mime = meta.split(';')[0];
            if (mime && mime.slice(0, 6) !== 'image/') isImage = false;
            if (!mime) isImage = false;
            if (isImage && mime !== 'image/svg+xml') {
              const payload = comma < 0 ? '' : url.slice(comma + 1);
              const head = /;base64/.test(meta) ? globalThis.atob(payload.slice(0, 16)) : decodeURIComponent(payload.slice(0, 24));
              isImage = /^(\x89PNG|GIF8|\xff\xd8|RIFF|BM|\x00\x00\x01\x00|<svg|<\?xml)/.test(head);
            }
          } else if (globalThis.__pt_blobs) {
            const b = __pt_blobs.get(url);
            if (b && !/^image\//.test(String(b.type || ''))) isImage = false;
          }
        } catch (e) {}
        // Итог декодирования — задача после уже поставленных сообщений, как в
        // браузере (декодер отвечает из другого потока).
        setTimeout(() => this.__ptFireLoad(isImage), 0);
        return;
      }
      if (typeof globalThis.__pt_subresource !== 'function') return;
      __pt_subresource(url, 'img').then(
        () => { this.__ptImgDone = true; this.__ptFireLoad(true); },
        () => { this.__ptImgDone = true; this.__ptFireLoad(false); },
      );
    }

    __ptFireLoad(ok) {
      const type = ok ? 'load' : 'error';
      // Рассылки достаточно: она сама зовёт и `onload`, и слушателей. Мы звали
      // обработчик ещё и напрямую, и он срабатывал дважды на каждой картинке и
      // каждом кадре — счётчик загрузок у страницы получался вдвое больше.
      // Событие шлёт движок, а движок здесь — браузер: `isTrusted` у него
      // истина. Недоверенная загрузка кадра или картинки — примета не хуже
      // недоверенного `load` у окна.
      try { this.dispatchEvent && this.dispatchEvent(__ptTrust(new Event(type))); } catch (e) {}
    }
    // `script.text` — тот же текст, что и textContent, и присвоение ему
    // запускает скрипт. Мы его молча проглатывали: у нас это было обычное
    // свойство, а `s.text = <исходник>; head.appendChild(s)` — как раз то, чем
    // челлендж объявляет свои функции верхнего уровня. Одна такая пропажа
    // роняла его интерпретатор на вызове несуществующей глобали.
    get text() {
      const t = this.tagName;
      if (t === 'SCRIPT' || t === 'TITLE' || t === 'OPTION' || t === 'A') return this.textContent || '';
      return __ptGetA(this, 'text');
    }
    set text(v) {
      this.textContent = String(v);
      if (this.__ptLocal === 'script' && this.isConnected && this.__ptRunScript) this.__ptRunScript();
    }
    // `srcdoc` — документ, написанный прямо в атрибуте: у него нет адреса, и
    // отражается он как есть. Присвоение после вставки в документ означает
    // новый документ в этом окне, как навигация.
    get srcdoc() { const v = __ptGetA(this, 'srcdoc'); return v === null ? '' : v; }
    set srcdoc(v) {
      __ptSetA(this, 'srcdoc', v);
      if (this.__ptLocal !== 'iframe') return;
      try {
        const w = this.__ptRealm || (this.isConnected ? this.__ptRealmWindow() : null);
        if (w && typeof w.__pt_writeDocument === 'function') w.__pt_writeDocument(String(v));
      } catch (e) {}
    }
    get sandbox() { return __ptGetA(this, 'sandbox') || ''; }
    set sandbox(v) { __ptSetA(this, 'sandbox', v); }
    get allow() { return __ptGetA(this, 'allow') || ''; }
    set allow(v) { __ptSetA(this, 'allow', v); }
    get href() { return this.__ptUrlAttr('href'); }
    set href(v) {
      __ptSetA(this, 'href', v);
      // `<link>` — тоже запрос: предзагрузка, стиль, значок. Браузер идёт за
      // ними сам, а мы не ходили ни за одним, и `rel=preload` не отправлял
      // ничего вовсе.
      if (this.__ptLocal === 'link' && this.__ptLoadLink) this.__ptLoadLink();
    }

    __ptLoadLink() {
      const rel = String(__ptGetA(this, 'rel') || '').toLowerCase();
      // Загружаемые виды: остальные (`alternate`, `canonical`, `dns-prefetch`)
      // в браузере запроса не делают.
      if (!/^(stylesheet|preload|prefetch|modulepreload|icon|shortcut icon|apple-touch-icon|manifest|prerender)$/.test(rel)) return;
      const raw = __ptGetA(this, 'href');
      if (!raw) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (this.__ptLinkAt === url) return;
      Object.defineProperty(this, '__ptLinkAt', { value: url, configurable: true, enumerable: false });
      // Таблица стилей, записанная прямо в адрес, — тоже таблица: браузер её
      // разбирает, не выходя в сеть.
      if (url.slice(0, 5) === 'data:') {
        if (rel === 'stylesheet') {
          try {
            const comma = url.indexOf(',');
            const head = url.slice(5, comma);
            const raw = url.slice(comma + 1);
            const text = /;base64$/i.test(head) ? atob(raw) : decodeURIComponent(raw);
            Object.defineProperty(this, '__ptSheetText',
              { value: text, writable: true, enumerable: false, configurable: true });
            __markDirty();
          } catch (e) {}
        }
        if (this.__ptFireLoad) __pt_soon(() => this.__ptFireLoad(true));
        return;
      }
      if (url.slice(0, 5) === 'blob:' || typeof globalThis.__pt_subresource !== 'function') return;
      // Всё, что пришло через `<link>`, браузер называет `link` в перечне
      // ресурсов — и предзагрузку, и значок, и таблицу стилей.
      const kind = rel === 'stylesheet' ? 'stylesheet' : 'link';
      // Таблица из разметки задерживает скрипты, что идут за ней: браузер не
      // исполнит их, пока её не разберёт. У нас скрипты шли сразу, и всё, что
      // они мерили при запуске, мерилось по голой странице — api.js Turnstile
      // отдавал виджету место обёртки у правого края окна вместо центра.
      const blocking = rel === 'stylesheet' && !document.__ptCurScript
        && this.ownerDocument === document && document.__ptReady === 'loading';
      if (blocking) globalThis.__ptBlockingSheets = (globalThis.__ptBlockingSheets | 0) + 1;
      let released = false;
      const release = () => {
        if (!blocking || released) return;
        released = true;
        globalThis.__ptBlockingSheets = Math.max(0, (globalThis.__ptBlockingSheets | 0) - 1);
      };
      __pt_subresource(url, kind).then(
        (res) => {
          // Внешняя таблица стилей — это правила, а не просто запрос: у нас
          // её тело выбрасывалось, и `document.styleSheets[i].cssRules` был
          // пуст на любой настоящей странице (у Chrome их там три тысячи), а
          // каскад не видел ни одного правила из внешнего файла.
          const wanted = rel === 'stylesheet';
          const take = (text) => {
            if (wanted && typeof text === 'string') {
              Object.defineProperty(this, '__ptSheetText',
                { value: text, writable: true, enumerable: false, configurable: true });
              __markDirty();
            }
            release();
            if (this.__ptFireLoad) this.__ptFireLoad(true);
          };
          if (wanted && res && typeof res.text === 'function') {
            res.text().then(take, () => take(null));
          } else take(null);
        },
        () => { release(); if (this.__ptFireLoad) this.__ptFireLoad(false); },
      );
    }

    // A link reflects the parts of its URL, and parsing a URL by assigning it to a
    // throwaway `<a>` and reading the pieces back is one of the oldest idioms on
    // the web — Cloudflare's challenge does it, and got `undefined` where it
    // expected a hostname, then died reading a property of that. Only `<a>` and
    // `<area>` have these; anything else reports `undefined`, as in a browser.
    get protocol() { const u = this.__ptLinkURL(); return u && u.protocol; }
    set protocol(v) { this.__ptSetLinkPart('protocol', v); }
    get host() { const u = this.__ptLinkURL(); return u && u.host; }
    set host(v) { this.__ptSetLinkPart('host', v); }
    get hostname() { const u = this.__ptLinkURL(); return u && u.hostname; }
    set hostname(v) { this.__ptSetLinkPart('hostname', v); }
    get port() { const u = this.__ptLinkURL(); return u && u.port; }
    set port(v) { this.__ptSetLinkPart('port', v); }
    get pathname() { const u = this.__ptLinkURL(); return u && u.pathname; }
    set pathname(v) { this.__ptSetLinkPart('pathname', v); }
    get search() { const u = this.__ptLinkURL(); return u && u.search; }
    set search(v) { this.__ptSetLinkPart('search', v); }
    get hash() { const u = this.__ptLinkURL(); return u && u.hash; }
    set hash(v) { this.__ptSetLinkPart('hash', v); }
    get origin() { const u = this.__ptLinkURL(); return u && u.origin; }
    get username() { const u = this.__ptLinkURL(); return u && (u.username || ''); }
    get password() { const u = this.__ptLinkURL(); return u && (u.password || ''); }
    __ptLinkURL() {
      const tag = this.__ptLocal;
      if (tag !== 'a' && tag !== 'area') return undefined;
      const raw = __ptGetA(this, 'href');
      if (raw == null) return undefined;
      const base = (globalThis.location && location.href) || 'about:blank';
      try { return new URL(raw, base); } catch (e) { return undefined; }
    }
    __ptSetLinkPart(part, v) {
      const u = this.__ptLinkURL();
      if (!u) return;
      try { u[part] = v; __ptSetA(this, 'href', u.href); } catch (e) {}
    }
    get action() { return this.__ptUrlAttr('action'); }
    set action(v) { __ptSetA(this, 'action', v); }
    __ptUrlAttr(n) {
      const raw = __ptGetA(this, n);
      if (raw == null) return '';
      const base = (globalThis.location && location.href) || 'about:blank';
      try { return new URL(raw, base).href; } catch (e) { return raw; }
    }

    // Plain string/boolean reflections a page can read back off an element.
    get rel() { return __ptGetA(this, 'rel') || ''; }
    set rel(v) { __ptSetA(this, 'rel', v); }
    get target() { return __ptGetA(this, 'target') || ''; }
    set target(v) { __ptSetA(this, 'target', v); }
    get alt() { return __ptGetA(this, 'alt') || ''; }
    set alt(v) { __ptSetA(this, 'alt', v); }
    get integrity() { return __ptGetA(this, 'integrity') || ''; }
    set integrity(v) { __ptSetA(this, 'integrity', v); }
    get nonce() { return __ptGetA(this, 'nonce') || ''; }
    set nonce(v) { __ptSetA(this, 'nonce', v); }
    get crossOrigin() { return __ptHasA(this, 'crossorigin') ? (__ptGetA(this, 'crossorigin') || 'anonymous') : null; }
    set crossOrigin(v) { __ptSetA(this, 'crossorigin', v); }
    get referrerPolicy() { return __ptGetA(this, 'referrerpolicy') || ''; }
    set referrerPolicy(v) { __ptSetA(this, 'referrerpolicy', v); }
    get async() { return __ptHasA(this, 'async'); }
    set async(v) { v ? __ptSetA(this, 'async', '') : __ptDelA(this, 'async'); }
    get defer() { return __ptHasA(this, 'defer'); }
    set defer(v) { v ? __ptSetA(this, 'defer', '') : __ptDelA(this, 'defer'); }
    // `'noModule' in script` — как страница спрашивает, умеет ли браузер модули.
    // Без этого свойства мы для любой сборки Vite — браузер из позапрошлой эпохи,
    // и нам присылают legacy-половину.
    get noModule() { return __ptHasA(this, 'nomodule'); }
    set noModule(v) { v ? __ptSetA(this, 'nomodule', '') : __ptDelA(this, 'nomodule'); }
    get hreflang() { return __ptGetA(this, 'hreflang') || ''; }
    set hreflang(v) { __ptSetA(this, 'hreflang', v); }
    get content() { return __ptGetA(this, 'content') || ''; }
    set content(v) { __ptSetA(this, 'content', v); }
    get httpEquiv() { return __ptGetA(this, 'http-equiv') || ''; }
    set httpEquiv(v) { __ptSetA(this, 'http-equiv', v); }
    get loading() { return __ptGetA(this, 'loading') || 'auto'; }
    set loading(v) { __ptSetA(this, 'loading', v); }
    get maxLength() { const v = parseInt(__ptGetA(this, 'maxlength'), 10); return Number.isFinite(v) ? v : -1; }
    set maxLength(v) { __ptSetA(this, 'maxlength', String(v)); }
    get minLength() { const v = parseInt(__ptGetA(this, 'minlength'), 10); return Number.isFinite(v) ? v : -1; }
    set minLength(v) { __ptSetA(this, 'minlength', String(v)); }
    get defaultValue() { return __ptGetA(this, 'value') || ''; }
    set defaultValue(v) { __ptSetA(this, 'value', v); }
    // Поля, которые участвуют в проверке формы: у неотключённой кнопки или
    // поля это `true`, и страницы это читают.
    get willValidate() {
      const t = String(__ptGetA(this, 'type') || '').toLowerCase();
      if (this.__ptLocal !== 'input' && this.__ptLocal !== 'textarea' && this.__ptLocal !== 'select') return undefined;
      return !__ptHasA(this, 'disabled') && !__ptHasA(this, 'readonly')
             && t !== 'hidden' && t !== 'button' && t !== 'reset';
    }
    // Список маркеров, а не строка: `rel`, `sandbox`, `relList` в браузере
    // это `DOMTokenList`, и страница читает у них `length` и перебирает.
    get relList() { return makeClassList(this, 'rel'); }
    get sandbox() { return makeClassList(this, 'sandbox'); }
    get htmlFor() { return __ptGetA(this, 'for') || ''; }
    set htmlFor(v) { __ptSetA(this, 'for', v); }

    get children() { return __collection(this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get nextElementSibling() { let n = this.nextSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.nextSibling; return n; }
    get previousElementSibling() { let n = this.previousSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.previousSibling; return n; }

    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }

    // Queries (scoped to this subtree)
    // getElementById у Element браузер не имеет — только у документа и фрагмента.
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByTagNameNS(ns, local) { return __collection(__tagsNS(this, ns, local)); }
    getElementsByClassName(c) {
      const cs = String(c).split(/\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = (e.__ptAttrs.get('class') || '').split(/\s+/);
        return cs.length > 0 && cs.every((x) => own.indexOf(x) >= 0);
      }));
    }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return query(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'))[0] || null;
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    closest(sel) {
      __needArgs(arguments.length, 1, 'closest', 'Element');
      __checkSelector(sel, 'closest', 'Element');
      for (let e = this; e; e = e.parentNode) if (e.nodeType === ELEMENT_NODE && matchesSelector(e, sel, this)) return e;
      return null;
    }
    matches(sel) {
      __needArgs(arguments.length, 1, 'matches', 'Element');
      return matchesSelector(this, __checkSelector(sel, 'matches', 'Element'), this);
    }

    // Serialization
    // --- iframes ----------------------------------------------------------
    // An iframe is a *browsing context*, not a tag: a widget creates one, then
    // polls `contentWindow` and refuses to proceed until it answers. Connecting
    // one queues a request the engine turns into a real child context; until it
    // is ready `contentWindow` is null, exactly as in a browser.
    get contentWindow() {
      // Present the moment the frame is connected, not once its document has
      // loaded — that is how a browser behaves (the window exists, `about:blank`
      // at first, and navigates afterwards). Waiting for the load was enough to
      // make widgets that poll this synchronously give up and start over.
      const st = __frames.get(this.__ptFrameId);
      if (st) return st.win;
      return this.__ptRealmWindow();
    }
    get contentDocument() {
      const st = __frames.get(this.__ptFrameId);
      // A cross-origin frame exposes no document at all — that is the rule, not a
      // limitation, and a networked frame's document lives in another context we
      // cannot hand back. A blank same-origin frame is a different matter: it has
      // a real realm of its own (below), and its document comes with it.
      if (st) return st.ready && st.sameOrigin ? st.doc || null : null;
      const w = this.__ptRealmWindow();
      return w ? w.document || null : null;
    }

    // A same-origin `<iframe>` with no `src` is a *window*, immediately — with its
    // own untouched natives. Code reaches into one synchronously
    // (`contentWindow.eval`, `contentWindow.Function`) precisely because a fresh
    // realm is where a patched function can be compared against a clean one; an
    // anti-bot VM that finds `null` there stops dead. The realm is a second V8
    // context in this same isolate, so its global is an ordinary object we can
    // hand back and the page can use directly.
    __ptRealmWindow() {
      if (this.__ptLocal !== 'iframe' || !this.isConnected) return null;
      if (this.__ptRealm) return this.__ptRealm;
      const src = __ptGetA(this, 'src');
      if (src && src !== 'about:blank') return null;
      if (typeof globalThis.__pt_makeRealm !== 'function') return null;
      const w = globalThis.__pt_makeRealm();
      if (!w) return null;
      // Таймеры реалма крутит очередь родителя: у самого реалма водителя нет.
      try { if (typeof globalThis.__pt_addChildRealm === 'function') __pt_addChildRealm(w); } catch (e) {}
      // Трассы реализации (холст, WebGPU) из реалма пишут в консоль родителя:
      // консоль реалма движок не читает. Только под флагом трассы.
      if (globalThis.__pt_canvasTrace || globalThis.__pt_gpuTrace || globalThis.__pt_encTrace) {
        try { Object.defineProperty(w, '__pt_parentConsole', { value: globalThis.__pt_parentConsole || console, configurable: true }); } catch (e) {}
      }
      // It is a child: it sees us as its parent, and knows the element it is in.
      for (const [k, v] of [['parent', globalThis], ['top', globalThis.top || globalThis],
        ['frameElement', this], ['self', w], ['window', w]]) {
        try { Object.defineProperty(w, k, { value: v, configurable: true }); } catch (e) {}
      }
      // Песочница наследует стороннесть кадра: разрешения и Notification в ней
      // отвечают как в нём.
      try { Object.defineProperty(w, '__pt_crossSite', { value: !!globalThis.__pt_crossSite, configurable: true }); } catch (e) {}
      // Окно пустого кадра внутри стороннего кадра у Chrome не знает ни
      // внешнего размера, ни положения на экране: outerWidth/outerHeight и
      // screenX/screenY там нули (так отвечает отчёт челленджа).
      // Уточнено 27.09 по эталону без пробников: внешний размер у такого окна —
      // размер окна браузера (как у окна кадра), положение на экране — 0.
      if (globalThis.__pt_crossSite) {
        const outer = { outerWidth: globalThis.outerWidth | 0, outerHeight: globalThis.outerHeight | 0 };
        for (const k of ['outerWidth', 'outerHeight', 'screenX', 'screenY', 'screenLeft', 'screenTop']) {
          try { const d = Object.getOwnPropertyDescriptor(w, k); Object.defineProperty(w, k, { value: k in outer ? outer[k] : 0, writable: true, enumerable: d ? d.enumerable : true, configurable: true }); } catch (e) {}
        }
      }
      // Происхождение `about:blank` — от создателя: origin и document.domain
      // отвечают его словами, адрес остаётся about:blank.
      try {
        Object.defineProperty(w, '__pt_inheritedOrigin', { value: (globalThis.location && location.origin) || 'null', configurable: true });
        Object.defineProperty(w, '__pt_inheritedHost', { value: (globalThis.location && location.hostname) || '', configurable: true });
      } catch (e) {}
      Object.defineProperty(this, '__ptRealm', { value: w, configurable: true, enumerable: false });
      try { __realmFrames.add(this); } catch (e) {}
      // Окно кадра — его собственная коробка, а не окно страницы. Кадр
      // 300×150 внутри так и отвечает, и тело в нём шириной 284, как в
      // браузере; мы отдавали ширину страницы.
      // Размер — заявленный, без раскладки: строить её ради окна пустого
      // кадра стоило 7–11 мс на каждую вставку и 87 мс на первую, а программа
      // челленджа вставляет такие кадры подряд и меряет себя часами. Точный
      // размер кадр получит с ближайшей раскладкой — её итог раздаётся всем
      // окнам кадров.
      try {
        // Скрыт сам или любым предком (через хозяев теневых корней): окно
        // такого кадра у Chrome 0×0.
        let hidden = false;
        for (let p = this; p && p.nodeType === ELEMENT_NODE; p = p.parentNode && p.parentNode.nodeType === 11 && p.parentNode.__ptHost ? p.parentNode.__ptHost : p.parentNode) {
          if (String((p.style && p.style.display) || '') === 'none' || __ptHasA(p, 'hidden')) { hidden = true; break; }
        }
        // Сторонний кадр без коробки (0×0) Chrome не раскладывает вовсе:
        // его пустые кадры остаются без размера — innerWidth 0.
        if (!hidden && __ptHiddenFrame()) hidden = true;
        // Сторонний кадр размером не больше 1×1 (виджет Turnstile в режиме
        // «невидимый») Chrome не отрисовывает: раскладка в нём не идёт, и
        // только что вставленные пустые кадры остаются без размера — 0×0
        // (эталон без пробников, секция Mrvi5). Видимость документа — прежняя.
        if (!hidden && globalThis.__pt_crossSite && (globalThis.innerWidth | 0) <= 1 && (globalThis.innerHeight | 0) <= 1) hidden = true;
        const [dw, dh] = __ptJSON.parse(__pt_frameBoxOf(this));
        // Трасса NOKK_TRACE_SRCDOC=1: чем окружён пустой кадр в миг создания.
        if (globalThis.__pt_srcdocTrace) {
          try {
            const chain = [];
            for (let p = this; p; p = p.parentNode && p.parentNode.nodeType === 11 && p.parentNode.__ptHost ? (chain.push('#shadow'), p.parentNode.__ptHost) : p.parentNode) {
              if (p.nodeType !== 1) { chain.push('#' + p.nodeType); break; }
              chain.push(p.localName + (p.id ? '#' + p.id : '') + (p.getAttribute('style') ? '[' + p.getAttribute('style') + ']' : '') + (p.className ? '.' + String(p.className).slice(0, 30) : ''));
            }
            let cs = ''; try { const c = getComputedStyle(this); cs = [c.display, c.width, c.height, c.visibility, c.position, c.left, c.top].join(','); } catch (e) {}
            (globalThis.__pt_parentConsole || console).error('[realm] ' + String(this.outerHTML).slice(0, 300) + ' | chain ' + chain.join(' < ') + ' | cs ' + cs + ' | box ' + dw + 'x' + dh + ' | hidden ' + hidden + ' | flat ' + (typeof __pt_inFlatTree === 'function' ? __pt_inFlatTree(this) : '?'));
          } catch (e) {}
        }
        __ptTellFrame(this, hidden ? null : { cw: dw, ch: dh });
      } catch (e) {}
      // Реферер и базовый адрес пустого кадра — документ-создатель, как у Chrome;
      // ставится до записи разметки: её скрипты уже читают document.referrer.
      try { Object.defineProperty(w, '__pt_creatorURL', { value: (globalThis.location && location.href) || '', configurable: true }); } catch (e) {}
      // Пустое окно — не пустой документ: у браузера там html/head/body, и
      // страница туда пишет. `srcdoc` кладётся тем же путём.
      try {
        const markup = __ptGetA(this, 'srcdoc');
        // Трасса NOKK_TRACE_SRCDOC=1: разметка srcdoc-кадра в консоль родителя.
        if (globalThis.__pt_srcdocTrace && markup != null) { try { (globalThis.__pt_parentConsole || console).error('[srcdoc] ' + String(markup).slice(0, 4000)); } catch (e) {} }
        // Адрес srcdoc-кадра у браузера — about:srcdoc.
        if (markup != null && typeof w.__pt_setLocation === 'function') w.__pt_setLocation({ href: 'about:srcdoc', protocol: 'about:', pathname: 'srcdoc', host: '', hostname: '', port: '', search: '', hash: '' });
        if (typeof w.__pt_writeDocument === 'function') w.__pt_writeDocument(markup || '');
      } catch (e) {}
      return w;
    }
    // A `<script>` that has just entered the document runs — once. The "already
    // started" flag is the spec's, and it is what keeps a parser-built script
    // (the engine runs those itself, in document order) from running twice, and a
    // re-inserted element from running again.
    __ptRunScript() {
      if (this.__ptRan || this.__ptLocal !== 'script') return;
      const type = String(__ptGetA(this, 'type') || '').toLowerCase().trim();
      // Anything that is not classic JS — a JSON island, a template, an importmap
      // — is data the page reads itself, not code to run.
      if (type && !/^(text|application)\/(java|ecma)script$|^module$/.test(type)) return;
      // `nomodule` — «это для браузера без модулей». Мы с модулями, значит мимо.
      if (type !== 'module' && __ptHasA(this, 'nomodule')) return;
      const src = __ptGetA(this, 'src');
      // Nothing to run *yet*: an element appended empty starts when its `src`
      // arrives, so the flag must not be set until there is something to do.
      if (!src && !this.textContent) return;
      Object.defineProperty(this, '__ptRan', { value: true, configurable: true, enumerable: false });
      // CSP: инлайн без nonce и чужой адрес не исполняются.
      if (globalThis.__pt_cspActive && __pt_cspActive()) {
        if (!src && __pt_cspBlocksInline(this)) return;
        if (src && __pt_cspBlocksScriptUrl(this, String(src))) return;
      }
      // Модуль исполняется не как обычный скрипт: у него свой разбор, свои
      // `import` и своя область. Такой отдаём движку — и со ссылкой, и вписанный
      // прямо в страницу.
      const isModule = type === 'module';
      if (src) {
        const id = __nextScriptId++;
        __scriptEls.set(id, this);
        __scriptOps.push({ op: 'load', id, src: String(src), module: isModule });
        return;
      }
      const code = this.textContent;
      if (!code) return;
      if (isModule) {
        const id = __nextScriptId++;
        __scriptEls.set(id, this);
        __scriptOps.push({ op: 'load', id, src: '', code: String(code), module: true });
        return;
      }
      // Не `eval`, а настоящий скрипт: V8 приписывает каждому кадру стека
      // «eval at <имя вызвавшей функции>», и наше внутреннее имя торчало в
      // следе вызовов любой страницы — метка, видная с первой же ошибки.
      // Запасной путь остаётся на случай сборки без этого встроенного.
      try {
        // Адрес — документа: у встроенного скрипта своего нет, и браузер
        // называет его кадры стека адресом страницы. Пустое имя превращало их
        // в `<anonymous>` — метку, видную всякому, кто читает `Error().stack`.
        let where_ = '';
        try { where_ = String((this.ownerDocument && this.ownerDocument.URL) || location.href || ''); } catch (e) {}
        const line = typeof __pt_markupLine === 'function' ? __pt_markupLine(String(code)) : 0;
        if (typeof __pt_evalScript === 'function') __pt_evalScript(String(code), where_, line > 0 ? line - 1 : 0);
        else (0, eval)(code);
      } catch (e) { __pt_reportError(e, 'inline script'); }
    }

    __ptConnectFrame() {
      if (this.__ptFrameId || this.__ptLocal !== 'iframe') return;
      const src = __ptGetA(this, 'src');
      // `about:blank` — не адрес, за которым идут в сеть: у браузера это тот же
      // начальный пустой документ, что и у кадра без src, и реалм в нём готов
      // сразу. Отличать их — значит ронять `f.src='about:blank';
      // body.appendChild(f); f.contentWindow.eval(…)`, а это штатный способ
      // взять нетронутые встроенные функции, которым челленджи и пользуются.
      const blank = !src || /^about:blank(\?|#|$)/.test(src.trim());
      if (blank) {
        // Кадр с `srcdoc` грузится сам, как только попал в документ, — ждать,
        // пока кто-нибудь прочитает `contentWindow`, браузер не заставляет.
        if (src || __ptGetA(this, 'srcdoc') !== null) { try { this.__ptRealmWindow(); } catch (e) {} }
        // Пустой документ тоже загружается: браузер сообщает `load` следующим
        // же оборотом. Мы молчали, и страница, ждущая `iframe.onload`, ждала
        // вечно — а это обычный способ дождаться готового кадра.
        if (!this.__ptBlankLoaded) {
          Object.defineProperty(this, '__ptBlankLoaded', { value: true, configurable: true, enumerable: false });
          // Пустой кадр у Chrome загружен уже при вставке: `load` уходит тут же,
          // в том же такте. Челлендж вставляет песочницу, ждёт load, снимает
          // окно и вынимает кадр за один оборот — у нас на это уходило полсекунды,
          // и окно мерилось ещё вставленным (300×150 вместо 0×0). Кадр с srcdoc
          // разбирается, и его load — следующим оборотом.
          if (__ptGetA(this, 'srcdoc') === null) { try { this.__ptFireLoad(true); } catch (e) {} }
          else __pt_soon(() => { try { this.__ptFireLoad(true); } catch (e) {} });
        }
        return;
      }
      const id = __nextFrameId++;
      Object.defineProperty(this, '__ptFrameId', { value: id, configurable: true, enumerable: false });
      // Размер элемента едет вместе с запросом: контекст кадра должен знать своё
      // окно до того, как в нём выполнится первая строка. Спрашивать раскладку
      // здесь нельзя — вставка идёт посреди разбора, и построенная в этот момент
      // раскладка застынет недостроенной; берём заявленный размер.
      const box = __ptJSON.parse(globalThis.__pt_frameBoxOf ? __pt_frameBoxOf(this) : '[300,150]');
      const st = { el: this, ready: false, sameOrigin: false, win: null, doc: null, pending: [] };
      st.win = __frameWindow(id, st);
      __frames.set(id, st);
      __frameOps.push({ op: 'open', id, src, w: box[0] || 300, h: box[1] || 150 });
    }

    // Shadow DOM. A widget that draws itself into a shadow root — Cloudflare's
    // Turnstile does, and so does most of the web-component world — dies at the
    // first line without this. The tree is genuinely separate: nothing inside is
    // reachable from `document.querySelector`, which is the point of it.
    attachShadow(init) {
      const m = init && init.mode;
      if (m !== 'open' && m !== 'closed') {
        throw new TypeError("Failed to execute 'attachShadow' on 'Element': Failed to read the 'mode' property from 'ShadowRootInit': The provided value '" + m + "' is not a valid enum value of type ShadowRootMode.");
      }
      if (this.__ptShadow) throw new (globalThis.DOMException || Error)("Failed to execute 'attachShadow' on 'Element': Shadow root cannot be created on a host which already hosts a shadow tree.", 'NotSupportedError');
      const sr = new ShadowRoot(this, m);
      sr.__ptDelegatesFocus = !!init.delegatesFocus;
      sr.__ptClonable = !!init.clonable;
      sr.__ptSerializable = !!init.serializable;
      sr.__ptSlotAssignment = init.slotAssignment === 'manual' ? 'manual' : 'named';
      this.__ptShadow = sr;
      __markDirty();
      return sr;
    }
    getAnimations() { return []; }
    getHTML(opts) {
      const kids = (this.__ptLocal === 'template' ? __templateContent(this) : this).__ptKids;
      const withShadow = !!(opts && opts.serializableShadowRoots);
      return kids.map((n) => serializeNode(n, withShadow)).join('');
    }
    get shadowRoot() {
      const r = this.__ptShadow;
      // A closed root is invisible even to its own host's `shadowRoot`.
      return r && r.mode === 'open' ? r : null;
    }

    get innerHTML() {
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      return host.__ptKids.map(serializeNode).join('');
    }
    set innerHTML(html) {
      // Разметка шаблона разбирается в его содержимое — таков разбор у него.
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      host.__ptKids = [];
      for (const n of parseFragment(String(html))) __ptAdd.call(host, n);
    }
    get outerHTML() { return serializeNode(this); }
    // Rendered text (hidden subtrees excluded, whitespace collapsed) — an
    // approximation of `innerText` good enough for tools that read it.
    get innerText() { return __innerText(this); }
    set innerText(v) { this.textContent = String(v); }
    get outerText() { return __innerText(this); }
    insertAdjacentHTML(pos, html) {
      __needArgs(arguments.length, 2, 'insertAdjacentHTML', 'Element');
      if (!/^(beforebegin|afterbegin|beforeend|afterend)$/i.test(String(pos))) {
        throw new (globalThis.DOMException || Error)(
          "Failed to execute 'insertAdjacentHTML' on 'Element': The value provided ('" + pos +
          "') is not one of 'beforeBegin', 'afterBegin', 'beforeEnd', or 'afterEnd'.",
          'SyntaxError');
      }
      const nodes = parseFragment(String(html));
      if (pos === 'beforeend') for (const n of nodes) __ptAdd.call(this, n);
      else if (pos === 'afterbegin') for (const n of nodes.reverse()) __ptInsert.call(this, n, this.firstChild);
      else if (pos === 'beforebegin') for (const n of nodes) __ptInsert.call(this.parentNode, n, this);
      else if (pos === 'afterend') for (const n of nodes.reverse()) __ptInsert.call(this.parentNode, n, this.nextSibling);
    }

    // Synthetic layout (no real rendering): rendered elements report a non-empty
    // box so coordinate + visibility tooling works, hidden/detached ones an empty
    // one. See __relayout / __boxOf below.
    getBoundingClientRect() { return __rectFromBox(__boxOf(this)); }
    getClientRects() { const b = __boxOf(this); if (!b) return __ptRectList([]); return __ptRectList([__rectFromBox(b)]); }
    get parentElement() { const p = this.parentNode; return p && p.nodeType === ELEMENT_NODE ? p : null; }
    // Layout-metric accessors derived from the synthetic box. `documentElement`'s
    // client size is the viewport (drivers clamp click boxes to it).
    // `clientWidth` — поле содержимого вместе с отступами, но без рамок, и
    // целым числом; `offsetWidth` — то же с рамками. Раньше оба отдавали одну
    // и ту же коробку, и элемент с рамкой отвечал на них одинаково.
    get clientWidth() { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement) return LAYOUT.W; const b = __boxOf(this); return b ? Math.round(b.w - b.bx - (b.bar ? b.bar[0] : 0)) : 0; }
    get clientHeight() { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement) return LAYOUT.H; const b = __boxOf(this); return b ? Math.round(b.h - b.by - (b.bar ? b.bar[1] : 0)) : 0; }
    get clientTop() { return 0; }
    get clientLeft() { return 0; }
    // Область прокрутки — по содержимому: `scrollWidth` у блока со скрытым
    // переполнением больше видимой части, и страницы это читают.
    get scrollWidth() { const b = __boxOf(this); return b ? Math.round(Math.max(this.clientWidth, b.sw)) : this.clientWidth; }
    get scrollHeight() { const b = __boxOf(this); return b ? Math.round(Math.max(this.clientHeight, b.sh)) : this.clientHeight; }
    get scrollTop() { return 0; }
    get scrollLeft() { return 0; }
    get offsetWidth() { const b = __boxOf(this); return b ? Math.round(b.w) : 0; }
    get offsetHeight() { const b = __boxOf(this); return b ? Math.round(b.h) : 0; }
    get offsetTop() { const b = __boxOf(this); return b ? b.y : 0; }
    get offsetLeft() { const b = __boxOf(this); return b ? b.x : 0; }
    get offsetParent() { return __boxOf(this) ? this.parentElement : null; }
    scrollIntoView() {} scrollIntoViewIfNeeded() {}
    focus() {
      const doc = this.ownerDocument || globalThis.document;
      if (!doc || doc.activeElement === this) return;
      const prev = doc.activeElement;
      // Порядок у браузера такой: `blur` и `focusout` на прежнем, потом `focus`
      // и `focusin` на новом; у каждого — второй участник в `relatedTarget`.
      // Событие шлёт сам браузер, поэтому `isTrusted` у него истина, даже когда
      // фокус попросили из скрипта. У нас были два события из четырёх, без
      // `relatedTarget` и недоверенные — а это читают.
      if (prev && prev !== doc.body && prev.dispatchEvent) {
        prev.dispatchEvent(__ptFocusEvent('blur', this));
        prev.dispatchEvent(__ptFocusEvent('focusout', this, true));
      }
      doc.__ptActive = this;
      // Тело — это «фокуса ни на ком»: у браузера в `relatedTarget` тогда
      // пусто, а не сам `<body>`.
      const откуда = prev && prev !== doc.body ? prev : null;
      this.dispatchEvent(__ptFocusEvent('focus', откуда));
      this.dispatchEvent(__ptFocusEvent('focusin', откуда, true));
    }
    blur() {
      const doc = this.ownerDocument || globalThis.document;
      if (!doc || doc.activeElement !== this) return;
      doc.__ptActive = doc.body || null;
      this.dispatchEvent(__ptFocusEvent('blur', null));
      this.dispatchEvent(__ptFocusEvent('focusout', null, true));
    }
    // Form-field value (reflects the `value` attribute until edited). Generic so
    // input/textarea typing works; harmless on other elements.
    get value() { return this.__ptValue !== undefined ? this.__ptValue : (__ptGetA(this, 'value') || ''); }
    set value(v) { this.__ptValue = String(v); }
    // Common form-field surface, reflected from attributes — drivers gate `fill`
    // and `select` on these (an input with no `type`/`disabled`/`readOnly` fails
    // Playwright's fillability check).
    // Неизвестное значение `type` у поля браузер сводит к `text`: страница,
    // которая ставит выдуманный тип и читает его назад, получает `text`.
    get type() {
      const t = (__ptGetA(this, 'type') || '').toLowerCase();
      if (this.tagName !== 'INPUT') return t;
      const KNOWN = ['button','checkbox','color','date','datetime-local','email','file','hidden',
                     'image','month','number','password','radio','range','reset','search','submit',
                     'tel','text','time','url','week'];
      return KNOWN.indexOf(t) >= 0 ? t : 'text';
    }
    set type(v) { __ptSetA(this, 'type', v); }
    get disabled() { return __ptHasA(this, 'disabled'); }
    set disabled(v) { if (v) __ptSetA(this, 'disabled', ''); else __ptDelA(this, 'disabled'); }
    get readOnly() { return __ptHasA(this, 'readonly'); }
    set readOnly(v) { if (v) __ptSetA(this, 'readonly', ''); else __ptDelA(this, 'readonly'); }
    get name() { return __ptGetA(this, 'name') || ''; }
    set name(v) { __ptSetA(this, 'name', v); }
    get placeholder() { return __ptGetA(this, 'placeholder') || ''; }
    // Reflected dimension attributes. Without these, `canvas.width = 200` would
    // create an *own* property on the element (real ones are prototype
    // accessors), which is exactly the tell we hide everywhere else.
    get width() {
      const v = parseInt(__ptGetA(this, 'width'), 10);
      if (Number.isFinite(v)) return v;
      if (this.tagName === 'CANVAS') return 300;
      // Без атрибута ширина картинки — её собственная, та, что в файле.
      return this.tagName === 'IMG' ? this.naturalWidth : 0;
    }
    set width(v) {
      __ptSetA(this, 'width', String(Math.max(0, v | 0)));
      // Смена размера холста сбрасывает состояние его контекста.
      if (this.__ptCtxResize) this.__ptCtxResize();
    }
    get height() {
      const v = parseInt(__ptGetA(this, 'height'), 10);
      if (Number.isFinite(v)) return v;
      if (this.tagName === 'CANVAS') return 150;
      return this.tagName === 'IMG' ? this.naturalHeight : 0;
    }
    set height(v) {
      __ptSetA(this, 'height', String(Math.max(0, v | 0)));
      if (this.__ptCtxResize) this.__ptCtxResize();
    }
    // Собственный размер картинки: ноль, пока она не загружена, и настоящий —
    // после. У нас его не было вовсе, и всё, что меряет нарисованное, видело
    // картинку нулевого размера.
    get naturalWidth() { const s = this.__ptImgSize(); return s ? s[0] : 0; }
    get naturalHeight() { const s = this.__ptImgSize(); return s ? s[1] : 0; }
    __ptImgSize() {
      if (this.tagName !== 'IMG' || !this.__ptImgDone || !this.__ptImgAt) return null;
      try { return globalThis.__pt_imageSizeOf ? __pt_imageSizeOf(this.__ptImgAt) : null; } catch (e) { return null; }
    }
    get checked() { return this.__ptChecked !== undefined ? this.__ptChecked : __ptHasA(this, 'checked'); }
    set checked(v) { this.__ptChecked = !!v; }
    get selectionStart() { return String(this.value || '').length; }
    get selectionEnd() { return String(this.value || '').length; }
    select() {}
    setSelectionRange() {}
    setRangeText() {}
    get isContentEditable() { const v = (__ptGetA(this, 'contenteditable') || '').toLowerCase(); return v === '' || v === 'true'; }
    click() { this.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); }

    __ptShallowClone() {
      const e = new Element(this.localName);
      e.__ptAttrs = new Map(this.__ptAttrs);
      // Клон стоит на той же ступени лестницы интерфейсов, что и оригинал:
      // копия `<template>` — тоже HTMLTemplateElement, а копия `<div>` —
      // HTMLDivElement. Без этого клон был просто Element, и всё, что живёт на
      // его интерфейсе, у копии пропадало.
      try {
        if (this.__ptNS && globalThis.__pt_svgProto) {
          const p = __pt_svgProto(this.localName);
          if (p) { Object.setPrototypeOf(e, p); e.__ptNS = this.__ptNS; }
        } else if (globalThis.__pt_elementProto) {
          Object.setPrototypeOf(e, __pt_elementProto(this.localName));
        }
      } catch (x) {}
      e.__ptDoc = this.ownerDocument;
      return e;
    }
  }

  // ---- Document -------------------------------------------------------------
  class Document extends Node {
    constructor() {
      super(DOCUMENT_NODE);
      this.__ptDocEl = null;
      this.__ptReady = 'loading';
      this.__ptCookie = '';
      this.__ptActive = null;
      this.__ptView = null;
      this.__ptCurScript = null;
    }
    get defaultView() { return this.__ptView; }
    set defaultView(v) { this.__ptView = v; }
    get currentScript() { return this.__ptCurScript; }
    set currentScript(v) { this.__ptCurScript = v; }
    // Сторонний кадр без коробки (0×0) у Chrome скрыт: его окно ещё не
    // показано, и `visibilityState` в нём и в его пустых кадрах — hidden.
    get visibilityState() { return globalThis.__ptDetached || __ptHiddenFrame() ? 'hidden' : 'visible'; }
    get hidden() { return !!globalThis.__ptDetached || __ptHiddenFrame(); }
    get documentElement() { return this.__ptDocEl; }
    // ParentNode у документа — своё, а не наследованное: у браузера
    // `children` лежит на `Document.prototype`, и без него поверхность
    // ставила заглушку, отвечавшую пустым объектом вместо коллекции.
    get children() { return __collection(this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.nodeType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE);
      return k.length ? k[k.length - 1] : null;
    }
    set documentElement(v) { this.__ptDocEl = v; }
    get readyState() { return this.__ptReady; }
    // Окно у человека в фокусе; DevTools-окно Chrome отвечает false, живое — true.
    hasFocus() { return !globalThis.__ptDetached; }
    set readyState(v) { this.__ptReady = v; }
    // В браузере это `<body>`, как только тело есть, и никогда не null у
    // загруженного документа: сборщик отпечатка кладёт его в корзину объектов,
    // а null — в корзину «x».
    get activeElement() { return this.__ptActive || this.body || null; }
    set activeElement(v) { this.__ptActive = v; }
    elementFromPoint(x, y) { return __elementFromPoint(x, y); }
    getAnimations() { return []; }
    // DOMImplementation: у нас была заглушка без методов, а
    // `document.implementation.createHTMLDocument()` — обычный способ взять
    // чистый документ.
    get implementation() {
      if (this.__ptImpl) return this.__ptImpl;
      const self = this;
      const impl = {
        createHTMLDocument(title) {
          const d = globalThis.__pt_lateDom.parseDocument('<!doctype html><html><head></head><body></body></html>', 'text/html');
          if (title !== undefined) { const t = d.createElement('title'); __ptAdd.call(t, d.createTextNode(String(title))); __ptAdd.call(d.head, t); }
          return d;
        },
        createDocument(ns, qname, doctype) {
          const d = globalThis.__pt_lateDom.parseDocument(qname ? '<' + String(qname) + '/>' : '', ns === 'http://www.w3.org/1999/xhtml' ? 'application/xhtml+xml' : 'application/xml');
          if (!qname) { for (const k of d.__ptKids.slice()) d.removeChild(k); }
          return d;
        },
        createDocumentType(name, publicId, systemId) { return { nodeType: 10, name: String(name), publicId: String(publicId || ''), systemId: String(systemId || ''), nodeName: String(name) }; },
        hasFeature() { return true; },
      };
      try { const D = globalThis.DOMImplementation; if (D && D.prototype) { for (const k of Object.keys(impl)) { Object.defineProperty(D.prototype, k, { value: impl[k], writable: true, enumerable: true, configurable: true }); } const o = Object.create(D.prototype); Object.defineProperty(this, '__ptImpl', { value: o, configurable: true }); return o; } } catch (e) {}
      Object.defineProperty(this, '__ptImpl', { value: impl, configurable: true });
      return impl;
    }
    // `document.all` — коллекция всех элементов в порядке дерева (у Chrome
    // она «необнаружима» — typeof undefined; этого V8 нам не даёт, зато по
    // индексу она отвечает, а не роняет читающего).
    // Только светлое дерево: теневые корни в document.all не входят (у нас
    // кадр виджета отвечал 96 элементов против 12 у Chrome).
    get all() { return __allCollection(collect(this, () => true)); }
    get applets() { return __collection([]); }
    // Не один элемент, а вся стопка под точкой: браузер отдаёт цепочку от
    // самого глубокого до `<html>`.
    elementsFromPoint(x, y) {
      const out = [];
      for (let e = __elementFromPoint(x, y); e && e.nodeType === ELEMENT_NODE; e = e.parentNode) out.push(e);
      // Точка в окне всегда попадает хотя бы в <html>: пустой стопки у
      // браузера не бывает, пока точка внутри вида.
      if (!out.length && this.documentElement && x >= 0 && y >= 0 && x < (globalThis.innerWidth || 0) && y < (globalThis.innerHeight || 0)) out.push(this.documentElement);
      return out;
    }
    get nodeName() { return '#document'; }
    get head() { return this.documentElement && __tags(this.documentElement, 'head')[0] || null; }
    get body() { return this.documentElement && __tags(this.documentElement, 'body')[0] || null; }
    get title() { const t = this.documentElement ? __tags(this.documentElement, 'title')[0] : null; return t ? t.textContent.trim() : ''; }
    set title(v) {
      let t = this.documentElement ? __tags(this.documentElement, 'title')[0] : null;
      if (!t) { t = this.createElement('title'); (this.head || this.documentElement || this).appendChild(t); }
      t.textContent = String(v);
    }
    // The document's live element collections. Missing, these are not a cosmetic
    // gap: Turnstile's loader answers its widget's `requestExtraParams` with a
    // report that reads `document.scripts.length`, and a `TypeError` there kills
    // the reply — which the widget waits for forever, silently, because a listener
    // that throws is swallowed by the event dispatch. `referrer` is read on the
    // same line and must be a string ('' for a direct load), not `undefined`.
    // Коллекции документа — это HTMLCollection, а не массив: `Array.isArray`
    // на них ложен, а сборщик отпечатка кладёт массив в корзину по его
    // строковому значению, из-за чего пустой список выглядел как пустая строка.
    get scripts() { return __collection(__docTags(this, 'script')); }
    get forms() { return __collection(__docTags(this, 'form')); }
    get images() { return __collection(__docTags(this, 'img')); }
    get embeds() { return __collection(__docTags(this, 'embed')); }
    get plugins() { return __collection(__docTags(this, 'embed')); }
    // `links` is `<a>`/`<area>` *with an href*, and `anchors` is `<a>` with a name.
    get links() {
      return __collection(__docTags(this, 'a').concat(__docTags(this, 'area'))
        .filter(e => __ptHasA(e, 'href')));
    }
    get anchors() { return __collection(__docTags(this, 'a').filter(e => __ptHasA(e, 'name'))); }
    get styleSheets() { return __styleSheetList(__sheetOwners(this)); }
    // Кодировка — объявленная, а не всегда UTF-8: страница без объявления
    // разбирается как windows-1252, и Chrome именно это и сообщает. Отвечать
    // «UTF-8» на документ, который ничего не объявил, — заметная разница.
    get characterSet() {
      if (this.__ptCharset) return this.__ptCharset;
      // Документы из строки (DOMParser) — всегда UTF-8.
      if (this.__ptContentType) return 'UTF-8';
      for (const m of __docTags(this, 'meta')) {
        const c = __ptGetA(m, 'charset');
        if (c) return __normEncoding(c);
        if (/^content-type$/i.test(__ptGetA(m, 'http-equiv') || '')) {
          const hit = /charset\s*=\s*"?([\w-]+)/i.exec(__ptGetA(m, 'content') || '');
          if (hit) return __normEncoding(hit[1]);
        }
      }
      // Пустой документ (`about:blank`, песочница челленджа) у браузера в UTF-8.
      return this.URL === 'about:blank' ? 'UTF-8' : 'windows-1252';
    }
    get charset() { return this.characterSet; }
    get inputEncoding() { return this.characterSet; }
    get contentType() { return this.__ptContentType || 'text/html'; }
    get xmlVersion() { return this.__ptXml ? '1.0' : null; }
    // Страница без `<!DOCTYPE>` живёт в режиме совместимости, и браузер это
    // говорит: `BackCompat` и `doctype === null`. Мы отвечали «стандартный
    // режим» всегда и выдавали объект-заглушку вместо узла.
    get compatMode() { return this.__ptDoctype || this.__ptXml ? 'CSS1Compat' : 'BackCompat'; }
    get doctype() { return this.__ptDoctype || null; }
    get designMode() { return 'off'; }
    set designMode(v) {}
    // Формат браузера — MM/DD/YYYY HH:MM:SS, а не локализованная строка.
    get lastModified() {
      const d = new Date(), p2 = (n) => String(n).padStart(2, '0');
      return `${p2(d.getMonth() + 1)}/${p2(d.getDate())}/${d.getFullYear()} ` +
             `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
    }
    get webkitVisibilityState() { return this.visibilityState; }
    get adoptedStyleSheets() { return this.__ptAdopted || (this.__ptAdopted = []); }
    set adoptedStyleSheets(v) { this.__ptAdopted = v; }
    // В браузере у документа textContent равен null — узла-контейнера нет.
    get textContent() { return null; }
    set textContent(v) {}

    // У `about:blank` в кадре реферер — документ-создатель.
    // У srcdoc-кадра Chrome отвечает только источником создателя («http://host/»).
    get referrer() { return this.__ptReferrer || (this.URL === 'about:blank' && globalThis.__pt_creatorURL) || (this.URL === 'about:srcdoc' && globalThis.__pt_creatorURL && (() => { try { return new URL(globalThis.__pt_creatorURL).origin + '/'; } catch (e) { return globalThis.__pt_creatorURL; } })()) || (this === globalThis.document && globalThis.__pt_referrer) || ''; }
    set referrer(v) { this.__ptReferrer = String(v); }

    // `document.location` is `window.location` — the same object, not a copy. Its
    // absence is not a missing nicety: `document.location.hostname` is how a great
    // deal of code asks where it is, and against `undefined` that throws. It is
    // what stopped Cloudflare's full-page challenge here, inside its own timer,
    // where nothing surfaced the error.
    // У документа без окна (DOMParser, XHR) `location` — null.
    get location() { return this === globalThis.document ? globalThis.location : null; }
    set location(v) { try { globalThis.location.href = String(v); } catch (e) {} }
    get URL() { return (globalThis.location && globalThis.location.href) || 'about:blank'; }
    get documentURI() { return this.URL; }
    // У `about:blank` базовый адрес — адрес создателя (запасной по спецификации).
    __ptBaseURI() { return (this.URL === 'about:blank' || this.URL === 'about:srcdoc') && globalThis.__pt_creatorURL ? globalThis.__pt_creatorURL : this.URL; }
    get domain() { return (globalThis.location && globalThis.location.hostname) || globalThis.__pt_inheritedHost || ''; }
    set domain(v) { /* only ever narrowed to a parent domain; nothing to do here */ }

    get cookie() { return this.__ptCookie; }
    set cookie(v) {
      const pair = String(v).split(';')[0];
      const eq = pair.indexOf('=');
      if (eq < 0) return;
      const name = pair.slice(0, eq).trim();
      const jar = this.__ptCookie ? this.__ptCookie.split('; ') : [];
      const kept = jar.filter(c => c.split('=')[0] !== name);
      kept.push(pair.trim());
      this.__ptCookie = kept.join('; ');
    }

    createElement(tag) {
      // Имя тега — по правилам XML: `1x` и `a b` браузер отвергает словами
      // InvalidCharacterError, а мы строили элемент с любым именем.
      const raw = String(tag);
      if (!/^[A-Za-z_:\u00C0-\u{10FFFF}][A-Za-z0-9_:.\-\u00B7\u00C0-\u{10FFFF}]*$/u.test(raw)) {
        throw new (globalThis.DOMException || Error)("Failed to execute 'createElement' on 'Document': The tag name provided ('" + raw + "') is not a valid name.", 'InvalidCharacterError');
      }
      // В XML-документе имя хранится как есть, а элемент — просто Element.
      if (this.__ptXml) {
        const e = new Element(raw);
        e.__ptTag = raw; e.__ptLocal = raw;
        try { if (globalThis.Element && globalThis.Element.prototype) Object.setPrototypeOf(e, globalThis.Element.prototype); } catch (x) {}
        e.__ptDoc = this;
        return e;
      }
      const C = __customs.get(raw.toLowerCase());
      if (globalThis.__pt_setPendingTag) __pt_setPendingTag(tag);
      const e = C ? new C() : new Element(tag);
      if (C) Object.defineProperty(e, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
      // Элемент стоит на своей ступени лестницы интерфейсов: `<canvas>` — на
      // HTMLCanvasElement, неизвестный тег — на HTMLUnknownElement.
      if (!C && globalThis.__pt_elementProto) {
        try { Object.setPrototypeOf(e, __pt_elementProto(tag)); } catch (x) {}
      }
      e.__ptDoc = this;
      return e;
    }
    createElementNS(ns, qname) {
      const q = String(qname), colon = q.indexOf(':');
      const prefix = colon > 0 ? q.slice(0, colon) : null, tag = colon > 0 ? q.slice(colon + 1) : q;
      const NS = ns === null || ns === undefined || ns === '' ? null : String(ns);
      const e = this.createElement(tag);
      e.__ptNS = NS;
      if (prefix) { e.__ptPrefix = prefix; e.__ptTag = q; }
      // Не-HTML элемент: имя как написано, без перевода в заглавные.
      if (NS !== 'http://www.w3.org/1999/xhtml') { e.__ptLocal = tag; e.__ptTag = q; }
      if (NS === 'http://www.w3.org/2000/svg' && globalThis.__pt_svgProto) {
        const proto = __pt_svgProto(String(tag));
        // Имя тега в SVG регистрозависимо: `clipPath`, не `clippath`.
        // И `tagName` у SVG — как написано (`text`, `clipPath`), а не заглавными.
        if (proto) { try { Object.setPrototypeOf(e, proto); e.__ptNS = String(ns); e.__ptLocal = String(tag); e.__ptTag = q; } catch (x) {} }
      } else if (NS === 'http://www.w3.org/1998/Math/MathML' && typeof globalThis.MathMLElement === 'function') {
        try { Object.setPrototypeOf(e, MathMLElement.prototype); } catch (x) {}
      } else if (NS !== 'http://www.w3.org/1999/xhtml' && NS !== 'http://www.w3.org/2000/svg') {
        try { Object.setPrototypeOf(e, Element.prototype); } catch (x) {}
      }
      return e;
    }
    createTextNode(t) { const n = new Text(t); n.__ptDoc = this; return n; }
    createComment(t) { const n = new Comment(t); n.__ptDoc = this; return n; }
    createDocumentFragment() { const f = new DocumentFragment(); f.__ptDoc = this; return f; }
    createEvent() { return new Event(''); }
    // Копия чужого узла для этого документа. Имени хватало в перечне свойств,
    // а вызов возвращал пустоту — и страница, которая кладёт содержимое
    // шаблона в тело (челлендж Cloudflare делает ровно это), спотыкалась на
    // следующей строке: `replaceChild(undefined, …)`.
    importNode(node, deep) {
      __needArgs(arguments.length, 1, 'importNode', 'Document');
      __needNode(node, 1, 'importNode', 'Document');
      if (node.nodeType === DOCUMENT_NODE) {
        throw new (globalThis.DOMException || Error)(
          "Failed to execute 'importNode' on 'Document': The node provided is a document, " +
          "which may not be imported.", 'NotSupportedError');
      }
      const copy = node.cloneNode(!!deep);
      __walkTree(copy, (n) => { n.__ptDoc = this; });
      return copy;
    }
    // Тот же узел, но уже наш: у прежнего родителя его больше нет.
    adoptNode(node) {
      __needArgs(arguments.length, 1, 'adoptNode', 'Document');
      __needNode(node, 1, 'adoptNode', 'Document');
      if (node.nodeType === DOCUMENT_NODE) {
        throw new (globalThis.DOMException || Error)(
          "Failed to execute 'adoptNode' on 'Document': The node provided is a document, " +
          "which may not be adopted.", 'NotSupportedError');
      }
      if (node.parentNode) node.parentNode.removeChild(node);
      __walkTree(node, (n) => { n.__ptDoc = this; });
      return node;
    }

    // Обход — от самого документа: <html> тоже его потомок. Прежде корнем был
    // documentElement, и он сам в выборку не попадал (getElementsByTagName('*')
    // давал на один меньше, чем querySelectorAll, id на <html> не находился).
    getElementById(id) { return firstMatch(this, (e) => e.id === String(id)); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) {
      const cs = String(c).split(/\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = ((e.__ptAttrs && e.__ptAttrs.get('class')) || '').split(/\s+/);
        return cs.length > 0 && cs.every((x) => own.indexOf(x) >= 0);
      }));
    }
    getElementsByName(n) {
      const want = String(n);
      return __staticNodeList(collect(this, (e) => e.__ptAttrs && e.__ptAttrs.get('name') === want));
    }
    getElementsByTagNameNS(ns, local) { return __collection(__tagsNS(this, ns, local)); }
    querySelector(s) {
      __needArgs(arguments.length, 1, 'querySelector', 'Document');
      __checkSelector(s, 'querySelector', 'Document');
      return query(this, s)[0] || null;
    }
    querySelectorAll(s) {
      __needArgs(arguments.length, 1, 'querySelectorAll', 'Document');
      __checkSelector(s, 'querySelectorAll', 'Document');
      return __staticNodeList(query(this, s));
    }

    // document.write inserts parsed markup at the position of the script that
    // called it (tracked as `currentScript`), matching in-parse behaviour for the
    // common `<script>document.write(x)</script>` idiom. With no current script
    // (e.g. async), it appends to <body>. Dynamically written <script> tags are
    // inserted but not executed (our script list is fixed at parse time).
    write(...args) {
      const nodes = parseFragment(args.join(''));
      const cur = this.currentScript;
      if (cur && cur.parentNode) {
        const ref = cur.nextSibling;
        for (const n of nodes) cur.parentNode.insertBefore(n, ref);
      } else {
        const host = this.body || this.documentElement;
        if (host) for (const n of nodes) host.appendChild(n);
      }
    }
    writeln(...args) { this.write(args.join('') + '\n'); }
    open() { return this; }
    close() {}
    __ptShallowClone() { return new Document(); }
  }

  // ---- Event ----------------------------------------------------------------
  // Event state lives in one hidden bag (`__ptE`) exposed through prototype
  // accessors: a real `new MouseEvent('click')` reports no own properties, so
  // assigning fields to the instance would be an obvious tell.
  const evtAccessors = (Ctor, names) => {
    for (const n of names) {
      const get = function () { return this.__ptE[n]; };
      const set = function (v) { this.__ptE[n] = v; };
      try { Object.defineProperty(get, 'name', { value: 'get ' + n, configurable: true }); } catch (e) {}
      try { Object.defineProperty(set, 'name', { value: 'set ' + n, configurable: true }); } catch (e) {}
      Object.defineProperty(Ctor.prototype, n, { get, set, configurable: true, enumerable: false });
    }
  };

  // `isTrusted` у браузера — собственное свойство каждого события
  // ([LegacyUnforgeable]), а не аксессор прототипа: перечисление прототипа
  // Event его не показывает, а у экземпляра оно неперенастраиваемое.
  const __ptIsTrustedGet = (() => {
    const g = function () { return !!(this.__ptE && this.__ptE.isTrusted); };
    try { Object.defineProperty(g, 'name', { value: 'get isTrusted', configurable: true }); } catch (e) {}
    return globalThis.__pt_native ? __pt_native(g) : g;
  })();
  class Event {
    constructor(type, init) {
      init = init || {};
      Object.defineProperty(this, 'isTrusted', { get: __ptIsTrustedGet, set: undefined, enumerable: true, configurable: false });
      this.__ptE = {
        type, bubbles: !!init.bubbles, cancelable: !!init.cancelable,
        // `composed` — обычное поле события, и у браузера оно false, а не
        // пустота: читают его наравне с `bubbles`.
        composed: !!init.composed,
        defaultPrevented: false, target: null, currentTarget: null,
        // Событие, созданное страницей, не доверенное — доверенные приходят
        // только от движка (ввод, load, message), и он метит их __ptTrust.
        eventPhase: 0, timeStamp: (globalThis.performance && performance.now()) || 0, isTrusted: false,
      };
      this.__ptStop = false; this.__ptStopImm = false;
    }
    preventDefault() { if (this.cancelable) this.__ptE.defaultPrevented = true; }
    stopPropagation() { this.__ptStop = true; }
    stopImmediatePropagation() { this.__ptStop = true; this.__ptStopImm = true; }
    // Путь той же рассылки; вне её — пусто, как у Chrome. Узлы закрытой тени
    // не видны слушателю снаружи неё.
    composedPath() {
      const p = this.__ptE ? this.__ptE.__ptPathNow : this.__ptPathNow; if (!p) return [];
      const cur = this.currentTarget; const out = [];
      let hidden = false;
      for (let i = 0; i < p.length; i++) {
        const n = p[i];
        out.push(n);
        if (n.nodeType === 11 && n.mode === 'closed' && cur && cur !== n && !(n.contains && n.contains(cur))) hidden = true;
        if (hidden && n.nodeType === 11) { out.length = 0; hidden = false; }
      }
      return out;
    }
  }
  // Пометить событие как пришедшее от движка. Страница до этого не дотянется:
  // имя __pt-скрыто из любого перечисления, а слепок делается один раз.
  const __ptTrust = (ev) => {
    if (ev && ev.__ptE) ev.__ptE.isTrusted = true;
    else if (ev) { try { Object.defineProperty(ev, 'isTrusted', { value: true, configurable: true }); } catch (e) {} }
    return ev;
  };
  // Воркерная область объявляется отдельным скриптом и метит свои доставки этим.
  try { Object.defineProperty(globalThis, '__pt_trustEvent', { value: __ptTrust, enumerable: false, configurable: true }); } catch (e) {}

  evtAccessors(Event, ['type', 'bubbles', 'cancelable', 'composed', 'defaultPrevented', 'target',
    'currentTarget', 'eventPhase', 'timeStamp']);

  class CustomEvent extends Event {
    constructor(type, init) { super(type, init); this.__ptE.detail = (init && init.detail) || null; }
  }
  evtAccessors(CustomEvent, ['detail']);

  class UIEvent extends Event {
    constructor(type, init) {
      super(type, init); init = init || {};
      this.__ptE.detail = init.detail || 0;
      this.__ptE.view = globalThis;
      // Устройство, породившее событие: у собранного страницей — null; ввод
      // мыши движок помечает сам (InputDeviceCapabilities, см. __pt_mouse).
      this.__ptE.sourceCapabilities = init.sourceCapabilities || null;
      this.__ptE.which = init.which || 0;
    }
  }
  evtAccessors(UIEvent, ['detail', 'view', 'which', 'sourceCapabilities']);

  const MODS = ['ctrlKey', 'shiftKey', 'altKey', 'metaKey'];
  const modifierState = function (k) {
    return { Control: this.ctrlKey, Shift: this.shiftKey, Alt: this.altKey, Meta: this.metaKey }[k] || false;
  };

  class MouseEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      const x = init.clientX || 0, y = init.clientY || 0;
      Object.assign(this.__ptE, {
        clientX: x, clientY: y,
        screenX: init.screenX || x, screenY: init.screenY || y,
        pageX: x, pageY: y,
        offsetX: init.offsetX || 0, offsetY: init.offsetY || 0,
        button: init.button || 0, buttons: init.buttons || 0,
        ctrlKey: !!init.ctrlKey, shiftKey: !!init.shiftKey,
        altKey: !!init.altKey, metaKey: !!init.metaKey,
        relatedTarget: init.relatedTarget || null,
        // x/y — те же clientX/Y; layerX/Y и сдвиг у собранного страницей
        // события — от его координат; which — кнопка плюс один (легаси Blink).
        x, y, layerX: Math.trunc(x), layerY: Math.trunc(y),
        movementX: init.movementX || 0, movementY: init.movementY || 0,
        which: (init.button || 0) + 1,
      });
    }
    get fromElement() { const t = this.type; return t === 'mouseover' || t === 'mouseenter' || t === 'pointerover' || t === 'pointerenter' ? this.relatedTarget : this.target; }
    get toElement() { const t = this.type; return t === 'mouseout' || t === 'mouseleave' || t === 'pointerout' || t === 'pointerleave' ? this.relatedTarget : this.target; }
    getModifierState(k) { return modifierState.call(this, k); }
  }
  evtAccessors(MouseEvent, ['clientX', 'clientY', 'screenX', 'screenY', 'pageX', 'pageY',
    'offsetX', 'offsetY', 'button', 'buttons', 'relatedTarget', 'movementX', 'movementY',
    'x', 'y', 'layerX', 'layerY'].concat(MODS));

  class PointerEvent extends MouseEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      // Умолчания — по спецификации, а не «как удобнее»: событие, собранное
      // страницей вручную, у Chrome отвечает `pointerId` 0, `pointerType` пустой
      // строкой и нулевым нажимом. Настоящие значения ставит тот, кто вводит.
      Object.assign(this.__ptE, {
        pointerId: init.pointerId === undefined ? 0 : init.pointerId,
        pointerType: init.pointerType === undefined ? '' : init.pointerType,
        isPrimary: !!init.isPrimary,
        width: init.width === undefined ? 1 : init.width,
        height: init.height === undefined ? 1 : init.height,
        pressure: init.pressure === undefined ? 0 : init.pressure,
        tangentialPressure: init.tangentialPressure || 0,
        tiltX: init.tiltX || 0,
        tiltY: init.tiltY || 0,
        twist: init.twist || 0,
        altitudeAngle: init.altitudeAngle === undefined ? Math.PI / 2 : init.altitudeAngle,
        azimuthAngle: init.azimuthAngle || 0,
      });
    }
    // Список слитых событий у ненастоящего события пуст — это его и выдаёт.
    getCoalescedEvents() { return this.isTrusted ? [this] : []; }
    getPredictedEvents() { return []; }
  }
  evtAccessors(PointerEvent, ['pointerId', 'pointerType', 'isPrimary', 'width', 'height',
    'pressure', 'tangentialPressure', 'tiltX', 'tiltY', 'twist', 'altitudeAngle', 'azimuthAngle']);

  class KeyboardEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        key: init.key || '', code: init.code || '',
        keyCode: init.keyCode || 0, which: init.keyCode || 0, charCode: init.charCode || 0,
        location: init.location || 0, repeat: !!init.repeat,
        ctrlKey: !!init.ctrlKey, shiftKey: !!init.shiftKey,
        altKey: !!init.altKey, metaKey: !!init.metaKey,
      });
    }
    getModifierState(k) { return modifierState.call(this, k); }
  }
  evtAccessors(KeyboardEvent, ['key', 'code', 'keyCode', 'which', 'charCode',
    'location', 'repeat'].concat(MODS));

  class InputEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        data: init.data == null ? null : String(init.data),
        inputType: init.inputType || '', isComposing: false,
      });
    }
  }
  evtAccessors(InputEvent, ['data', 'inputType', 'isComposing']);

  class FocusEvent extends UIEvent {
    constructor(type, init) { super(type, init); this.__ptE.relatedTarget = (init && init.relatedTarget) || null; }
  }
  evtAccessors(FocusEvent, ['relatedTarget']);

  class MessageEvent extends Event {
    constructor(type, init) {
      super(type, init); init = init || {};
      this.__ptE.data = init.data !== undefined ? init.data : null;
      this.__ptE.origin = init.origin || '';
      this.__ptE.lastEventId = init.lastEventId || '';
      this.__ptE.source = init.source || null;
      this.__ptE.ports = init.ports || [];
    }
  }
  evtAccessors(MessageEvent, ['data', 'origin', 'lastEventId', 'source', 'ports']);

  for (const [n, C] of [['UIEvent', UIEvent], ['MouseEvent', MouseEvent], ['PointerEvent', PointerEvent],
    ['KeyboardEvent', KeyboardEvent], ['InputEvent', InputEvent], ['FocusEvent', FocusEvent],
    ['MessageEvent', MessageEvent]]) {
    if (!globalThis[n]) globalThis[n] = C;
  }

  // ---- Web Workers (single-threaded shim) -----------------------------------
  // Real Chrome exposes Worker/OffscreenCanvas/SharedWorker; a missing `typeof
  // Worker` is a passive fingerprint tell. This runs the worker script in an
  // emulated global scope in the same isolate (no real threading), so `typeof
  // Worker === "function"` holds and compute-style workers (message in → work →
  // postMessage back) function. Not real parallelism, and blob: scripts need
  // URL.createObjectURL support to load.
  // Воркер — отдельный контекст V8, который строит движок: своя область, свои
  // прототипы, свой `self`. Здесь остаётся только порт: очередь операций наружу
  // и доставка сообщений обратно.
  const __workerOps = [];
  const __workers = new Map();
  let __nextWorkerId = 1;
  globalThis.__pt_drainWorkerQueue = () => __workerOps.splice(0);
  globalThis.__pt_workerMessage = (id, json) => {
    const W = __workers.get(id);
    if (!W || W.closed) return;
    let data = null;
    try { data = __pt_cloneDecode(json); } catch (e) {}
    const ev = __ptTrust(new MessageEvent('message', { data, origin: '', source: null }));
    try { __ptEvSet(ev, 'target', W.worker); __ptEvSet(ev, 'currentTarget', W.worker); } catch (e) {}
    // Внутри обработчика `window.event` — это событие, снаружи ничего.
    const снимок = __ptTakeEvent(ev);
    let t0 = 0; try { t0 = performance.now(); } catch (e) {}
    try {
      try { if (typeof W.onmessage === 'function') W.onmessage.call(W.worker, ev); } catch (e) {}
      for (const h of (W.listeners.message || [])) { try { h.call(W.worker, ev); } catch (e) {} }
    } finally {
      try {
        const dt = performance.now() - t0;
        if (dt > 50 && typeof globalThis.__pt_noteLoaf === 'function') {
          const h = typeof W.onmessage === 'function' ? W.onmessage : (W.listeners.message || [])[0];
          __pt_noteLoaf(t0, dt, typeof W.onmessage === 'function' ? 'Worker.onmessage' : 'Worker.addEventListener:message', 'event-listener', h);
        }
      } catch (e) {}
      __ptDropEvent(снимок);
    }
  };
  globalThis.__pt_workerFailed = (id, message) => {
    const W = __workers.get(id);
    if (!W) return;
    const ev = new MessageEvent('error', {});
    ev.__ptE.message = String(message || 'worker failed');
    try { if (typeof W.onerror === 'function') W.onerror.call(W.worker, ev); } catch (e) {}
    for (const h of (W.listeners.error || [])) { try { h.call(W.worker, ev); } catch (e) {} }
  };

  class Worker extends EventTarget {
    constructor(scriptURL, options) {
      super();
      const id = __nextWorkerId++;
      const W = { id, onmessage: null, onmessageerror: null, onerror: null, closed: false, listeners: {}, worker: this };
      Object.defineProperty(this, '__ptW', { value: W, enumerable: false });
      __workers.set(id, W);
      // The bytes are taken now, not when the engine gets round to the op: a
      // browser starts fetching the script inside `new Worker`, and the common
      // idiom is `const u = URL.createObjectURL(b); new Worker(u);
      // URL.revokeObjectURL(u)` — read it a round later and the blob is gone.
      const src = String(scriptURL);
      let body = null;
      if (src.slice(0, 5) === 'blob:' || src.slice(0, 5) === 'data:') {
        try { body = globalThis.__pt_localSource ? __pt_localSource(src) : null; } catch (e) {}
      }
      __workerOps.push({ op: 'open', id, src, body, name: (options && options.name) || '' });
    }
    postMessage(data) {
      const W = this.__ptW;
      if (W.closed) return;
      let json = 'null';
      // Как в браузере: структурный клон, а не JSON, — иначе воркер получит
      // вместо байтов объект, а вместо даты строку.
      json = __pt_cloneEncode(data);
      __workerOps.push({ op: 'post', id: W.id, data: json });
    }
    terminate() {
      const W = this.__ptW;
      W.closed = true;
      __workers.delete(W.id);
      __workerOps.push({ op: 'close', id: W.id });
    }
    addEventListener(t, h) { const L = this.__ptW.listeners; (L[t] = L[t] || []).push(h); }
    removeEventListener(t, h) { const L = this.__ptW.listeners; if (L[t]) L[t] = L[t].filter((x) => x !== h); }
    dispatchEvent(ev) { (this.__ptW.listeners[ev.type] || []).forEach((h) => { try { h.call(this, ev); } catch (e) {} }); return true; }
  }
  for (const p of ['onmessage', 'onmessageerror', 'onerror']) {
    Object.defineProperty(Worker.prototype, p, {
      configurable: true,
      get() { return this.__ptW[p]; },
      set(v) { this.__ptW[p] = v; },
    });
  }
  // `Object.prototype.toString.call(new Worker(...))` — «[object Worker]», как у
  // всякого интерфейса; без тега объект называет себя простым Object.
  try { Object.defineProperty(Worker.prototype, Symbol.toStringTag, { value: 'Worker', configurable: true }); } catch (e) {}

  class SharedWorker {
    constructor(scriptURL, options) {
      const port = {
        onmessage: null, onmessageerror: null,
        postMessage() {}, start() {}, close() {},
        addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
      };
      Object.defineProperty(this, '__ptW', { value: { onerror: null, port } });
    }
    get port() { return this.__ptW.port; }
    get onerror() { return this.__ptW.onerror; }
    set onerror(v) { this.__ptW.onerror = v; }
  }

  // OffscreenCanvas maps to a detached <canvas>, reusing its 2D/WebGL contexts.
  class OffscreenCanvas {
    constructor(width, height) {
      // Через снятые заранее ссылки, а не через имена, которые видит
      // страница: в браузере `new OffscreenCanvas` не трогает ни
      // `document.createElement`, ни `HTMLCanvasElement.prototype.getContext`,
      // а у нас каждый офскрин тянул за собой лишний, видимый вызов.
      let c = globalThis.__pt_privateCanvas
        ? globalThis.__pt_privateCanvas(width, height)
        : (globalThis.document ? globalThis.document.createElement('canvas') : null);
      // В воркере документа нет вовсе, а OffscreenCanvas там есть и рисует —
      // ради него он в воркере и существует. Холст без документа: методы те же,
      // что у элемента, размеры свои. Без этого `getContext('2d')` в воркере
      // отдавал null, и сборщик, который снимает там отпечаток холста, молча
      // оставался ни с чем.
      if (!c) {
        // Холст-подставка наследует прототип элемента: методы холста
        // проверяют бренд, и чужой объект они отвергают, как и в браузере.
        const proto = globalThis.__pt_canvasProto;
        c = Object.create(proto || null);
        Object.defineProperty(c, 'localName', { value: 'canvas', writable: true, configurable: true });
        Object.defineProperty(c, 'width', { value: width | 0, writable: true, configurable: true });
        Object.defineProperty(c, 'height', { value: height | 0, writable: true, configurable: true });
      }
      c.width = width | 0; c.height = height | 0;
      Object.defineProperty(this, '__ptO', { value: { c, w: width | 0, h: height | 0 } });
    }
    get width() { return this.__ptO.w; }
    set width(v) {
      this.__ptO.w = v | 0;
      if (this.__ptO.c) this.__ptO.c.width = v | 0;
    }
    get height() { return this.__ptO.h; }
    set height(v) { this.__ptO.h = v | 0; if (this.__ptO.c) this.__ptO.c.height = v | 0; }
    getContext(type, attrs) {
      try { if (globalThis.__pt_canvasTrace) (globalThis.__pt_parentConsole || console).error('[холст getContext offscreen ' + (this.width | 0) + 'x' + (this.height | 0) + '] ' + String(type) + ' ' + JSON.stringify(attrs === undefined ? null : attrs)); } catch (e) {}
      // У офскрина свой набор имён: `experimental-webgl` и прочие браузер здесь
      // не принимает вовсе, а отвечает отказом.
      const t = String(type);
      if (t !== '2d' && t !== 'webgl' && t !== 'webgl2' && t !== 'bitmaprenderer' && t !== 'webgpu') {
        throw new TypeError("Failed to execute 'getContext' on 'OffscreenCanvas': The provided value '"
          + t + "' is not a valid enum value of type OffscreenRenderingContextType.");
      }
      const c = this.__ptO.c;
      const orig = globalThis.__pt_canvasOrig;
      const get = (orig && orig.getContext) || (c && c.getContext);
      const g = c && get ? get.call(c, t, attrs) : null;
      // Двумерный контекст офскрина — отдельный интерфейс, и страница читает
      // его имя: `OffscreenCanvasRenderingContext2D`, не `CanvasRenderingContext2D`.
      if (g && t === '2d' && globalThis.OffscreenCanvasRenderingContext2D) {
        try {
          const P = globalThis.OffscreenCanvasRenderingContext2D.prototype;
          if (P && Object.getPrototypeOf(g) !== P) {
            if (!P.__ptLinked) {
              const src = Object.getPrototypeOf(g);
              Object.setPrototypeOf(P, src);
              Object.defineProperty(P, '__ptLinked', { value: true });
              // Заглушки формы на месте настоящих членов уступают им: у
              // Chrome эти члены — собственные у офскринного контекста.
              try {
                const S = globalThis.__pt_stubMembers;
                for (const k of Object.getOwnPropertyNames(P)) {
                  const d = Object.getOwnPropertyDescriptor(P, k);
                  const real = Object.getOwnPropertyDescriptor(src, k);
                  if (d && real && S && ((d.value && S.has(d.value)) || (d.get && S.has(d.get)))) Object.defineProperty(P, k, real);
                }
              } catch (e) {}
              if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
                Object.defineProperty(P, Symbol.toStringTag,
                  { value: 'OffscreenCanvasRenderingContext2D', configurable: true });
              }
            }
            Object.setPrototypeOf(g, P);
          }
        } catch (e) {}
      }
      return g;
    }
    // Настоящая картинка, а не пустой `Blob`: страница, которая снимает холст
    // и меряет длину снимка, получала ноль.
    convertToBlob(opts) {
      const c = this.__ptO.c;
      const type = (opts && opts.type) || 'image/png';
      const orig = globalThis.__pt_canvasOrig;
      const url = (orig && orig.toDataURL) || (c && c.toDataURL);
      try {
        if (c && url && globalThis.__pt_blobFromDataUrl) {
          return Promise.resolve(globalThis.__pt_blobFromDataUrl(
            url.call(c, type, opts && opts.quality)));
        }
      } catch (e) { return Promise.reject(e); }
      return Promise.resolve(new Blob([], { type }));
    }
    // Настоящий ImageBitmap: он должен нести пиксели холста, иначе `drawImage`
    // им рисует пустоту. Возвращался пустой объект — сборщик отпечатков
    // получал из него ничего.
    transferToImageBitmap() {
      const c = this.__ptO.c;
      // Снимок собирается тем же помощником, что и `createImageBitmap`: у него
      // размеры на прототипе, тег имени и рабочий `close`, как в браузере.
      if (globalThis.__pt_makeBitmap) {
        return globalThis.__pt_makeBitmap(c && c.__ptSurf, this.__ptO.w, this.__ptO.h);
      }
      const b = Object.create((globalThis.ImageBitmap && globalThis.ImageBitmap.prototype) || Object.prototype);
      Object.defineProperty(b, '__ptImageBitmap', { value: { surf: c && c.__ptSurf } });
      Object.defineProperty(b, 'width', { value: this.__ptO.w, enumerable: true });
      Object.defineProperty(b, 'height', { value: this.__ptO.h, enumerable: true });
      Object.defineProperty(b, 'close', { value: function close() {}, writable: true, configurable: true });
      return b;
    }
  }

  // Свои же методы, снятые до страницы. Внутренние вставки не должны идти
  // через имена, которые страница может подменить: в браузере ни
  // `appendChild` изнутри `innerHTML`, ни `setAttribute` изнутри `new Image`
  // не видны никому, а у нас каждая такая мелочь всплывала в чужом крючке.
  const __ptInsert = Node.prototype.insertBefore;
  const __ptAdd = Node.prototype.appendChild;
  const __ptDrop = Node.prototype.removeChild;
  const __ptSetAttr = Element.prototype.setAttribute;
  // Чтение и запись атрибутов изнутри движка. Свойства, отражающие атрибут
  // (`el.src`, `el.id`, `style.color`, `classList`), в браузере не зовут
  // `getAttribute`/`setAttribute` — это нативная работа, и крючок страницы её
  // не видит. У нас каждое такое присваивание всплывало чужим вызовом.
  const __ptAttrGet = Element.prototype.getAttribute;
  const __ptAttrSet = Element.prototype.setAttribute;
  const __ptAttrHas = Element.prototype.hasAttribute;
  const __ptAttrDel = Element.prototype.removeAttribute;
  const __ptGetA = (el, n) => __ptAttrGet.call(el, n);
  const __ptSetA = (el, n, v) => __ptAttrSet.call(el, n, v);
  const __ptHasA = (el, n) => __ptAttrHas.call(el, n);
  const __ptDelA = (el, n) => __ptAttrDel.call(el, n);

  // Холст для собственных нужд движка. Ни `document.createElement`, ни
  // `getContext` со страницы здесь не участвуют: всякий, кто их обернул — а
  // сборщики отпечатков оборачивают, — иначе видит нашу кухню
  // (`createImageBitmap`, WebGPU поверх GL) как свои вызовы, которых в
  // браузере на этом месте нет.
  globalThis.__pt_privateCanvas = (w, h) => {
    const orig = globalThis.__pt_canvasOrig;
    let c = null;
    if (globalThis.document) {
      c = (orig && orig.createElement)
        ? orig.createElement.call(globalThis.document, 'canvas')
        : globalThis.document.createElement('canvas');
    } else {
      // Подставка наследует прототип элемента: его методы проверяют бренд.
      const proto = globalThis.__pt_canvasProto;
      c = Object.create(proto || null);
      Object.defineProperty(c, 'localName', { value: 'canvas', writable: true, configurable: true });
      Object.defineProperty(c, 'width', { value: w | 0, writable: true, configurable: true });
      Object.defineProperty(c, 'height', { value: h | 0, writable: true, configurable: true });
    }
    if (c) { c.width = w | 0; c.height = h | 0; }
    return c;
  };
  globalThis.__pt_privateCtx = (c, type, attrs) => {
    if (!c) return null;
    const orig = globalThis.__pt_canvasOrig;
    const get = (orig && orig.getContext) || c.getContext;
    return get ? get.call(c, type, attrs) : null;
  };

  // Передача холста воркеру: сам метод ставится позже, из слоя невидимости —
  // таблица форм интерфейсов затирает его заглушкой, если поставить здесь.
  globalThis.__pt_makeTransferred = (canvas) => {
    const off = Object.create(OffscreenCanvas.prototype);
    Object.defineProperty(off, '__ptO', {
      value: { c: canvas, w: canvas.width | 0, h: canvas.height | 0 },
    });
    return off;
  };

  globalThis.Worker = Worker;
  globalThis.SharedWorker = SharedWorker;
  globalThis.OffscreenCanvas = OffscreenCanvas;

  // ---- helpers: classList, dataset, style -----------------------------------
  function makeClassList(el, attr) {
    const name = attr || 'class';
    const get = () => (__ptGetA(el, name) || '').split(/\s+/).filter(Boolean);
    const set = (arr) => __ptSetA(el, name, arr.join(' '));
    // Настоящий `DOMTokenList`, а не литерал: он перебирается, индексируется и
    // называет себя. `[...el.classList]` у нас бросал — а это одна из самых
    // ходовых строк на любой странице.
    const proto = (globalThis.DOMTokenList && globalThis.DOMTokenList.prototype) || Object.prototype;
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'DOMTokenList', configurable: true });
      }
    } catch (e) {}
    const api = Object.create(proto);
    Object.assign(api, {
      contains: (c) => get().includes(c),
      add: (...cs) => { const s = get(); for (const c of cs) if (!s.includes(c)) s.push(c); set(s); },
      remove: (...cs) => set(get().filter(c => !cs.includes(c))),
      toggle: (c, force) => { const s = get(); const has = s.includes(c);
        if (force === true || (force === undefined && !has)) { if (!has) s.push(c); set(s); return true; }
        set(s.filter(x => x !== c)); return false; },
      replace: (a, b) => { const s = get(); const i = s.indexOf(a); if (i < 0) return false; s[i] = b; set(s); return true; },
      supports: () => true,
      item: (i) => get()[i] || null,
      forEach(fn, self) { get().forEach((v, i) => fn.call(self, v, i, api)); },
      entries() { return get().entries(); },
      keys() { return get().keys(); },
      values() { return get().values(); },
      toString: () => get().join(' '),
      [Symbol.iterator]() { return get()[Symbol.iterator](); },
    });
    Object.defineProperty(api, 'length', { get: () => get().length, configurable: true });
    Object.defineProperty(api, 'value', {
      get: () => get().join(' '), set: (v) => __ptSetA(el, name, String(v)), configurable: true,
    });
    // Числовые ключи живые: список читается из атрибута при каждом обращении.
    return __ptProxy(api, {
      get(t, k, r) {
        if (typeof k === 'string' && /^\d+$/.test(k)) return get()[+k];
        return Reflect.get(t, k, r);
      },
      has(t, k) {
        if (typeof k === 'string' && /^\d+$/.test(k)) return +k < get().length;
        return Reflect.has(t, k);
      },
      ownKeys(t) {
        return get().map((_, i) => String(i)).concat(Reflect.ownKeys(t).filter((k) => typeof k !== 'string' || !/^\d+$/.test(k)));
      },
      getOwnPropertyDescriptor(t, k) {
        if (typeof k === 'string' && /^\d+$/.test(k)) {
          const v = get()[+k];
          return v === undefined ? undefined : { value: v, enumerable: true, configurable: true, writable: false };
        }
        return Reflect.getOwnPropertyDescriptor(t, k);
      },
    });
  }
  // ---- CSSOM ---------------------------------------------------------------
  // Настоящие таблицы стилей: `document.styleSheets` был списком литералов с
  // пустым `cssRules`, а сборщик Cloudflare читает его сотнями обращений в
  // начале второй стадии — правила, селекторы, cssText. Формы интерфейсов и
  // сериализация сняты с Chrome 148.
  //
  // Значения приводятся так же, как приводит браузер там, где это видно
  // невооружённым глазом: `0` в свойстве длины становится `0px`, комбинаторы
  // селектора разделяются пробелами, после двоеточия в условии @media — пробел.
  const CSS_LENGTH_PROPS = new Set([
    'width', 'height', 'min-width', 'min-height', 'max-width', 'max-height',
    'top', 'right', 'bottom', 'left', 'margin', 'margin-top', 'margin-right',
    'margin-bottom', 'margin-left', 'padding', 'padding-top', 'padding-right',
    'padding-bottom', 'padding-left', 'border-width', 'border-top-width',
    'border-right-width', 'border-bottom-width', 'border-left-width',
    'border-radius', 'font-size', 'letter-spacing', 'word-spacing', 'text-indent',
    'outline-width', 'column-gap', 'row-gap', 'gap', 'inset', 'border-spacing',
    'border', 'outline',
  ]);
  // Цвет в браузере не остаётся тем, чем его написали: `#f2f2f2` в cssText
  // возвращается как `rgb(242, 242, 242)`. Сверено с Chrome на таблице стилей
  // виджета Cloudflare — из 183 правил 73 расходились только этим.
  const __cssHex = (v) => v.replace(/#([0-9a-fA-F]{3,8})\b/g, (m, h) => {
    const wide = h.length > 4;
    if (h.length !== 3 && h.length !== 4 && h.length !== 6 && h.length !== 8) return m;
    const at = (i) => wide ? parseInt(h.slice(i * 2, i * 2 + 2), 16)
                           : parseInt(h[i] + h[i], 16);
    const [r, g, b] = [at(0), at(1), at(2)];
    if (h.length === 4 || h.length === 8) {
      const a = at(3) / 255;
      return 'rgba(' + r + ', ' + g + ', ' + b + ', ' + (Math.round(a * 100) / 100) + ')';
    }
    return 'rgb(' + r + ', ' + g + ', ' + b + ')';
  });
  // `.9` браузер печатает как `0.9`, и внутри функций тоже:
  // `cubic-bezier(.55, .085, …)` → `cubic-bezier(0.55, 0.085, …)`.
  const __cssZero = (v) => v.replace(/(^|[\s(,])(-?)\.(\d)/g, '$1$20.$3');

  // Сокращённая запись `animation` разбирается на восемь составляющих и
  // печатается всегда полностью, в порядке спецификации, с подставленными
  // начальными значениями: `spin 5s linear infinite` →
  // `5s linear 0s infinite normal none running spin`.
  const ANIM_TIMING = new Set(['ease', 'linear', 'ease-in', 'ease-out', 'ease-in-out',
                               'step-start', 'step-end']);
  const ANIM_DIR = new Set(['normal', 'reverse', 'alternate', 'alternate-reverse']);
  const ANIM_FILL = new Set(['none', 'forwards', 'backwards', 'both']);
  const ANIM_STATE = new Set(['running', 'paused']);
  const __cssTokens = (v) => {
    const out = [];
    let depth = 0, cur = '';
    for (const c of v) {
      if (c === '(') depth++;
      else if (c === ')') depth--;
      if (/\s/.test(c) && depth === 0) { if (cur) out.push(cur); cur = ''; continue; }
      cur += c;
    }
    if (cur) out.push(cur);
    return out;
  };
  const __cssAnimation = (v) => v.split(',').map((part) => {
    // Запятые внутри `cubic-bezier(…)` не делят список — склеиваем обратно.
    return part;
  }).reduce((acc, part) => {
    const prev = acc[acc.length - 1];
    if (prev !== undefined && (prev.split('(').length !== prev.split(')').length)) {
      acc[acc.length - 1] = prev + ',' + part;
    } else acc.push(part);
    return acc;
  }, []).map((one) => {
    const t = __cssTokens(one.trim());
    let dur = null, timing = null, delay = null, count = null;
    let dir = null, fill = null, state = null, name = null;
    for (const tok of t) {
      const low = tok.toLowerCase();
      if (/^-?[\d.]+m?s$/.test(low)) { if (dur === null) dur = low; else if (delay === null) delay = low; continue; }
      if (timing === null && (ANIM_TIMING.has(low) || /^(cubic-bezier|steps|linear)\(/.test(low))) { timing = tok; continue; }
      if (count === null && (low === 'infinite' || /^[\d.]+$/.test(low))) { count = low; continue; }
      if (dir === null && ANIM_DIR.has(low)) { dir = low; continue; }
      if (fill === null && ANIM_FILL.has(low)) { fill = low; continue; }
      if (state === null && ANIM_STATE.has(low)) { state = low; continue; }
      if (name === null) name = tok;
    }
    // Начальная длительность у браузера — `auto`, а не ноль секунд:
    // `animation: none` он печатает как `auto ease 0s 1 normal none running none`.
    return [dur || 'auto', timing || 'ease', delay || '0s', count || '1',
            dir || 'normal', fill || 'none', state || 'running', name || 'none'].join(' ');
  }).join(', ');

  // Как браузер печатает тень: сперва цвет, потом четыре длины с единицами,
  // и `inset` в конце. Автор пишет как придётся, а в CSSOM выходит всегда так.
  // Разбить список по запятым верхнего уровня: запятые внутри `rgb(…)` не
  // делят его.
  const __cssCommaParts = (v) => {
    const out = [];
    let depth = 0, cur = '';
    for (const c of String(v)) {
      if (c === '(') depth++;
      else if (c === ')') depth--;
      if (c === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
      cur += c;
    }
    out.push(cur);
    return out;
  };

  const __cssShadow = (v) => __cssCommaParts(v).map((one) => {
    const parts = __ptCssParts(one.trim());
    let colour = null, inset = false;
    const lens = [];
    for (const t of parts) {
      if (/^inset$/i.test(t)) { inset = true; continue; }
      if (/^[-\d.]/.test(t)) { lens.push(/^[-\d.]+$/.test(t) ? t + 'px' : t); continue; }
      colour = t;
    }
    if (!lens.length) return one.trim();
    // Число длин — как у автора: `1px 2px` браузер не дополняет размытием.
    // Слово браузер оставляет словом: `red` в правиле так и печатается, а вот
    // запись функцией приводится к своему виду — `rgba(0,0,0,.1)` становится
    // `rgba(0, 0, 0, 0.1)`.
    const norm = colour && /^(rgba?|hsla?|hwb|color|lab|lch|oklab|oklch)\(/i.test(colour)
      && globalThis.__pt_cssColour ? globalThis.__pt_cssColour(colour) : colour;
    const out = [norm || colour || 'currentcolor', ...lens];
    if (inset) out.push('inset');
    return out.join(' ');
  }).join(', ');

  // Обводка: цвет, начертание, толщина — в этом порядке.
  const __cssOutline = (v) => {
    const parts = __ptCssParts(v.trim());
    let colour = null, style = null, width = null;
    for (const t of parts) {
      const low = t.toLowerCase();
      if (CS_BORDER_STYLES.has(low)) { style = low; continue; }
      if (/^[-\d.]/.test(t) || CS_WIDTH_WORDS[low]) { width = /^[-\d.]+$/.test(t) ? t + 'px' : t; continue; }
      colour = t;
    }
    if (!style && !width) return v;
    return [colour || 'currentcolor', style || 'none', width || 'medium'].join(' ');
  };

  // Нули внутри преобразования получают единицы: `rotate(0)` браузер печатает
  // как `rotate(0deg)`, `translateY(0)` — как `translateY(0px)`.
  const __cssTransform = (v) => v.replace(/([a-zA-Z]+)\(([^()]*)\)/g, (m, fn, args) => {
    const low = fn.toLowerCase();
    const unit = /^(rotate|rotatex|rotatey|rotatez|rotate3d|skew|skewx|skewy)$/.test(low) ? 'deg'
      : /^(translate|translatex|translatey|translatez|translate3d|perspective)$/.test(low) ? 'px'
      : null;
    if (!unit) return m;
    const out = args.split(',').map((a, i) => {
      const t = a.trim();
      if (!/^-?\d+(?:\.\d+)?$/.test(t)) return t;
      // У `rotate3d` первые три числа — ось, без единиц.
      if (low === 'rotate3d' && i < 3) return t;
      if (low === 'translate3d' && i === 2) return t + 'px';
      return t + unit;
    });
    return fn + '(' + out.join(', ') + ')';
  });

  /// Список семейств так, как его печатает браузер: имя с пробелами берётся
  /// в двойные кавычки, одинарные переводятся в двойные, остальное как есть.
  const __cssFamilies = (v) => __cssCommaParts(v).map((one) => {
    const t = one.trim();
    if (!t) return t;
    const q = t[0];
    if (q === '"' || q === "'") {
      const inner = t.slice(1, t.length - (t[t.length - 1] === q ? 1 : 0));
      return '"' + inner + '"';
    }
    return /\s/.test(t) ? '"' + t + '"' : t;
  }).join(', ');

  // Имя свойства: встроенные — без регистра, собственные (`--*`) — с ним.
  // Мы приводили к строчным и те и другие, и `var(--Wide)` на chess.com не
  // находил объявленного `--Wide`: вся раскладка формы входа съезжала.
  const __cssKey = (p) => {
    const s = String(p).trim();
    return s.charCodeAt(0) === 45 && s.charCodeAt(1) === 45 ? s : s.toLowerCase();
  };
  // Числа в значениях браузер печатает шестью значащими цифрами:
  // `scale(1.000998)` становится `scale(1.001)`, `138.828125px` — `138.828px`.
  // Строки в кавычках и адреса не трогаются, как и знаки внутри слов
  // (`translate3d`, `#ff8800`).
  const __cssNum1 = (t) => {
    const n = Number(t);
    if (!isFinite(n)) return t;
    return String(Number(n.toPrecision(6)));
  };
  // Преобразование как матрица: `scale(1.000998)` → [a, b, c, d, e, f].
  const __parseTransform = (str) => {
    const src = String(str || '').trim();
    if (!src || src === 'none') return null;
    let M = [1, 0, 0, 1, 0, 0];
    let any = false;
    const mul = (n) => {
      const [a, b, c, d, e, f] = M; const [a2, b2, c2, d2, e2, f2] = n;
      M = [a * a2 + c * b2, b * a2 + d * b2, a * c2 + c * d2, b * c2 + d * d2, a * e2 + c * f2 + e, b * e2 + d * f2 + f];
    };
    const re = /([a-zA-Z0-9]+)\s*\(([^)]*)\)/g;
    let m;
    while ((m = re.exec(src))) {
      const fn = m[1].toLowerCase();
      const v = m[2].split(/[\s,]+/).filter(Boolean).map((x) => parseFloat(x));
      if (v.some((x) => !isFinite(x))) return null;
      any = true;
      const rad = (x) => (x || 0) * Math.PI / 180;
      switch (fn) {
        case 'matrix': if (v.length !== 6) return null; mul(v); break;
        case 'scale': mul([v[0], 0, 0, v.length > 1 ? v[1] : v[0], 0, 0]); break;
        case 'scalex': mul([v[0], 0, 0, 1, 0, 0]); break;
        case 'scaley': mul([1, 0, 0, v[0], 0, 0]); break;
        case 'scale3d': mul([v[0], 0, 0, v[1], 0, 0]); break;
        case 'translate': mul([1, 0, 0, 1, v[0] || 0, v[1] || 0]); break;
        case 'translatex': mul([1, 0, 0, 1, v[0] || 0, 0]); break;
        case 'translatey': mul([1, 0, 0, 1, 0, v[0] || 0]); break;
        case 'translate3d': mul([1, 0, 0, 1, v[0] || 0, v[1] || 0]); break;
        case 'rotate': { const c = Math.cos(rad(v[0])), sn = Math.sin(rad(v[0])); mul([c, sn, -sn, c, 0, 0]); break; }
        case 'skewx': mul([1, 0, Math.tan(rad(v[0])), 1, 0, 0]); break;
        case 'skewy': mul([1, Math.tan(rad(v[0])), 0, 1, 0, 0]); break;
        default: return null;
      }
    }
    return any ? M : null;
  };
  const __cssNumbers = (v) => v.replace(
    /("[^"]*"|'[^']*'|url\([^)]*\))|(?<![A-Za-z0-9_#.\-])([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)(?=[A-Za-z%]*(?![A-Za-z0-9_.#\-]))/g,
    (m, q, num) => (q ? q : __cssNum1(num)));
  const __cssValue = (prop, value) => {
    const r = __cssValueRaw(prop, value);
    if ((prop.charCodeAt(0) === 45 && prop.charCodeAt(1) === 45) || prop === 'unicode-range') return r;
    try { return __cssNumbers(r); } catch (e) { return r; }
  };
  const __cssValueRaw = (prop, value) => {
    // Значение собственного свойства браузер хранит как написано.
    if (prop.charCodeAt(0) === 45 && prop.charCodeAt(1) === 45) return String(value).trim();
    let v = __cssZero(__cssHex(String(value).trim().replace(/\s+/g, ' ')));
    if (prop === 'animation') return __cssAnimation(v);
    if (prop === 'box-shadow' || prop === 'text-shadow') return __cssShadow(v);
    if (prop === 'outline') return __cssOutline(v);
    if (prop === 'transform') return __cssTransform(v);
    // Косая черта в сетке печатается с пробелами по бокам.
    if (prop === 'grid-area' || prop === 'grid-row' || prop === 'grid-column') {
      return v.replace(/\s*\/\s*/g, ' / ');
    }
    // Одно слово в точке преобразования браузер дополняет вторым.
    if (prop === 'transform-origin' && /^[a-z%\d.-]+$/i.test(v) && !/\s/.test(v)) {
      return v + ' center';
    }
    // Список через запятую печатается с пробелом после запятой.
    if (prop === 'stroke-dasharray') return v.replace(/\s*,\s*/g, ', ');
    // Начальное значение `transition-property` браузер не печатает.
    if (prop === 'transition') return v.replace(/^all\s+/i, '');
    // Фон печатается в своём порядке: сперва картинка, цвет последним, а
    // голый адрес берётся в кавычки.
    if (prop === 'background') {
      const parts = __ptCssParts(v);
      const image = [], rest = [];
      let colour = null;
      for (const t of parts) {
        if (/^url\(/i.test(t)) {
          image.push(t.replace(/^url\(\s*(['"]?)(.*?)\1\s*\)$/i, (m, q, u) => 'url("' + u + '")'));
        } else if (/^(linear-gradient|radial-gradient|conic-gradient|image-set|-webkit-)/i.test(t)) image.push(t);
        else if (__ptIsColour(t)) colour = t;
        else rest.push(t);
      }
      if (!image.length && !colour) return v;
      return [...image, ...rest, ...(colour ? [colour] : [])].join(' ');
    }
    // В сокращении шрифта косая черта отделяется пробелами, а список
    // семейств печатается по тем же правилам, что и отдельное свойство.
    if (prop === 'font') {
      const spaced = v.replace(/\s*\/\s*/g, ' / ');
      const at = spaced.search(/(?:^|\s)(?:[\d.]+[a-z%]*|smaller|larger|x?x-(?:small|large)|small|medium|large)(?:\s*\/\s*\S+)?\s+/);
      if (at < 0) return spaced;
      const m = /(?:^|\s)(?:[\d.]+[a-z%]*|smaller|larger|x?x-(?:small|large)|small|medium|large)(?:\s*\/\s*\S+)?\s+/.exec(spaced);
      const head = spaced.slice(0, m.index + m[0].length);
      return head + __cssFamilies(spaced.slice(m.index + m[0].length));
    }
    // Список семейств: пробел после запятой, а имя из нескольких слов — в
    // двойных кавычках, как печатает браузер. Одинарные он переводит в двойные.
    if (prop === 'font-family') return __cssFamilies(v);
    // Составляющие сокращённой записи, равные начальному значению, браузер не
    // печатает: `flex-flow: column nowrap` возвращается как `column`.
    if (prop === 'flex-flow') v = v.replace(/\s+nowrap$/, '');
    if (!CSS_LENGTH_PROPS.has(prop)) return v;
    // Только на верхнем уровне: голый ноль в `border: 0` — это длина, а тройка
    // внутри `rgb(178, 15, 3)` — нет, и приписанный ей `px` ломает цвет.
    let depth = 0, out = '', tok = '';
    const flush = () => {
      if (tok && depth === 0 && /^-?\d+(?:\.\d+)?$/.test(tok)) out += tok + 'px';
      else out += tok;
      tok = '';
    };
    for (const c of v) {
      if (c === '(') { flush(); depth++; out += c; continue; }
      if (c === ')') { tok += c; out += tok; tok = ''; depth--; continue; }
      if (/\s/.test(c) && depth === 0) { flush(); out += c; continue; }
      tok += c;
    }
    flush();
    return out;
  };
  const __cssSelector = (sel) => String(sel).trim()
    .replace(/\s+/g, ' ')
    .replace(/\s*([>+~])\s*/g, ' $1 ')
    .replace(/\s*,\s*/g, ', ');
  const __cssPrelude = (p) => String(p).trim().replace(/\s+/g, ' ').replace(/:\s*/g, ': ');

  // Разбор: пролог до `{` или `;`, затем тело со счётом вложенности. Строки и
  // комментарии не считаются — иначе `content: "}"` рвёт правило пополам.
  // Экранирована ли кавычка: считать надо идущие подряд обратные косые, а не
  // одну. `content:"\\"` — это строка из одной косой, и кавычка после неё
  // закрывающая; мы считали её экранированной и теряли весь остаток файла
  // (на chess.com — семьсот шестьдесят правил из тысячи).
  const __cssEscaped = (text, i) => {
    let n = 0;
    while (i - 1 - n >= 0 && text[i - 1 - n] === '\\') n++;
    return (n & 1) === 1;
  };

  function __cssParse(text) {
    const out = [];
    const n = text.length;
    let i = 0;
    while (i < n) {
      while (i < n && /\s/.test(text[i])) i++;
      if (i >= n) break;
      if (text.startsWith('/*', i)) { const e = text.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
      const start = i;
      let depth = 0, q = null;
      while (i < n) {
        const c = text[i];
        if (q) { if (c === q && !__cssEscaped(text, i)) q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (depth === 0 && (c === '{' || c === ';')) break;
        i++;
      }
      const prelude = text.slice(start, i).trim();
      if (i >= n) { if (prelude) out.push({ prelude, statement: true }); break; }
      if (text[i] === ';') { i++; if (prelude) out.push({ prelude, statement: true }); continue; }
      i++;                                    // за '{'
      const bodyStart = i;
      let d = 1;
      q = null;
      while (i < n && d > 0) {
        const c = text[i];
        if (q) { if (c === q && !__cssEscaped(text, i)) q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '{') d++;
        else if (c === '}') d--;
        i++;
      }
      out.push({ prelude, body: text.slice(bodyStart, d === 0 ? i - 1 : i) });
    }
    return out;
  }

  function __cssDecls(body) {
    const map = new Map();
    let i = 0;
    const n = body.length;
    while (i < n) {
      const start = i;
      let depth = 0, q = null;
      while (i < n) {
        const c = body[i];
        if (q) { if (c === q && !__cssEscaped(body, i)) q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (c === ';' && depth === 0) break;
        i++;
      }
      const decl = body.slice(start, i).trim();
      i++;
      if (!decl) continue;
      const colon = decl.indexOf(':');
      if (colon <= 0) continue;
      const prop = __cssKey(decl.slice(0, colon));
      // Написанное дважды встаёт на второе место, а не остаётся на первом:
      // браузер при перезаписи убирает свойство и дописывает в конец.
      if (prop) {
        map.delete(prop);
        map.set(prop, __cssValue(prop, decl.slice(colon + 1)));
      }
    }
    return map;
  }

  // Блок объявлений правила: тот же интерфейс, что у `el.style`, но за ним
  // стоит карта правила, а не атрибут элемента.
  // Имена свойств CSS, как их держит Chrome 148 у каждого объявления стиля:
  // собственными свойствами объекта и в этом порядке. Их перечисляет любой
  // сборщик отпечатка — по ним видно и движок, и его версию.
  // Имена -epub-* Chrome убрал: их перечисление у нас давало девять лишних
  // свойств у вычисленного стиля, а челлендж перебирает его целиком.
  const CSS_PROPS = ["accentColor","additiveSymbols","alignContent","alignItems","alignSelf","alignmentBaseline","all","anchorName","anchorScope","animation","animationComposition","animationDelay","animationDirection","animationDuration","animationFillMode","animationIterationCount","animationName","animationPlayState","animationRange","animationRangeEnd","animationRangeStart","animationTimeline","animationTimingFunction","animationTrigger","appRegion","appearance","ascentOverride","aspectRatio","backdropFilter","backfaceVisibility","background","backgroundAttachment","backgroundBlendMode","backgroundClip","backgroundColor","backgroundImage","backgroundOrigin","backgroundPosition","backgroundPositionX","backgroundPositionY","backgroundRepeat","backgroundSize","basePalette","baselineShift","baselineSource","blockSize","border","borderBlock","borderBlockColor","borderBlockEnd","borderBlockEndColor","borderBlockEndStyle","borderBlockEndWidth","borderBlockStart","borderBlockStartColor","borderBlockStartStyle","borderBlockStartWidth","borderBlockStyle","borderBlockWidth","borderBottom","borderBottomColor","borderBottomLeftRadius","borderBottomRightRadius","borderBottomStyle","borderBottomWidth","borderCollapse","borderColor","borderEndEndRadius","borderEndStartRadius","borderImage","borderImageOutset","borderImageRepeat","borderImageSlice","borderImageSource","borderImageWidth","borderInline","borderInlineColor","borderInlineEnd","borderInlineEndColor","borderInlineEndStyle","borderInlineEndWidth","borderInlineStart","borderInlineStartColor","borderInlineStartStyle","borderInlineStartWidth","borderInlineStyle","borderInlineWidth","borderLeft","borderLeftColor","borderLeftStyle","borderLeftWidth","borderRadius","borderRight","borderRightColor","borderRightStyle","borderRightWidth","borderShape","borderSpacing","borderStartEndRadius","borderStartStartRadius","borderStyle","borderTop","borderTopColor","borderTopLeftRadius","borderTopRightRadius","borderTopStyle","borderTopWidth","borderWidth","bottom","boxDecorationBreak","boxShadow","boxSizing","breakAfter","breakBefore","breakInside","bufferedRendering","captionSide","caretAnimation","caretColor","caretShape","clear","clip","clipPath","clipRule","color","colorInterpolation","colorInterpolationFilters","colorRendering","colorScheme","columnCount","columnFill","columnGap","columnHeight","columnRule","columnRuleBreak","columnRuleColor","columnRuleInset","columnRuleInsetCap","columnRuleInsetCapEnd","columnRuleInsetCapStart","columnRuleInsetEnd","columnRuleInsetJunction","columnRuleInsetJunctionEnd","columnRuleInsetJunctionStart","columnRuleInsetStart","columnRuleStyle","columnRuleVisibilityItems","columnRuleWidth","columnSpan","columnWidth","columnWrap","columns","contain","containIntrinsicBlockSize","containIntrinsicHeight","containIntrinsicInlineSize","containIntrinsicSize","containIntrinsicWidth","container","containerName","containerType","content","contentVisibility","cornerBlockEndShape","cornerBlockStartShape","cornerBottomLeftShape","cornerBottomRightShape","cornerBottomShape","cornerEndEndShape","cornerEndStartShape","cornerInlineEndShape","cornerInlineStartShape","cornerLeftShape","cornerRightShape","cornerShape","cornerStartEndShape","cornerStartStartShape","cornerTopLeftShape","cornerTopRightShape","cornerTopShape","counterIncrement","counterReset","counterSet","cursor","cx","cy","d","descentOverride","direction","display","dominantBaseline","dynamicRangeLimit","emptyCells","fallback","fieldSizing","fill","fillOpacity","fillRule","filter","flex","flexBasis","flexDirection","flexFlow","flexGrow","flexLineCount","flexShrink","flexWrap","float","floodColor","floodOpacity","font","fontDisplay","fontFamily","fontFeatureSettings","fontKerning","fontLanguageOverride","fontOpticalSizing","fontPalette","fontSize","fontSizeAdjust","fontStretch","fontStyle","fontSynthesis","fontSynthesisSmallCaps","fontSynthesisStyle","fontSynthesisWeight","fontVariant","fontVariantAlternates","fontVariantCaps","fontVariantEastAsian","fontVariantEmoji","fontVariantLigatures","fontVariantNumeric","fontVariantPosition","fontVariationSettings","fontWeight","forcedColorAdjust","gap","grid","gridArea","gridAutoColumns","gridAutoFlow","gridAutoRows","gridColumn","gridColumnEnd","gridColumnGap","gridColumnStart","gridGap","gridRow","gridRowEnd","gridRowGap","gridRowStart","gridTemplate","gridTemplateAreas","gridTemplateColumns","gridTemplateRows","height","hyphenateCharacter","hyphenateLimitChars","hyphens","imageOrientation","imageRendering","inherits","initialLetter","initialValue","inlineSize","inset","insetBlock","insetBlockEnd","insetBlockStart","insetInline","insetInlineEnd","insetInlineStart","interactivity","interestDelay","interestDelayEnd","interestDelayStart","interpolateSize","isolation","justifyContent","justifyItems","justifySelf","left","letterSpacing","lightingColor","lineBreak","lineGapOverride","lineHeight","listStyle","listStyleImage","listStylePosition","listStyleType","margin","marginBlock","marginBlockEnd","marginBlockStart","marginBottom","marginInline","marginInlineEnd","marginInlineStart","marginLeft","marginRight","marginTop","marker","markerEnd","markerMid","markerStart","mask","maskClip","maskComposite","maskImage","maskMode","maskOrigin","maskPosition","maskRepeat","maskSize","maskType","mathDepth","mathShift","mathStyle","maxBlockSize","maxHeight","maxInlineSize","maxWidth","minBlockSize","minHeight","minInlineSize","minWidth","mixBlendMode","navigation","negative","objectFit","objectPosition","objectViewBox","offset","offsetAnchor","offsetDistance","offsetPath","offsetPosition","offsetRotate","opacity","order","orphans","outline","outlineColor","outlineOffset","outlineStyle","outlineWidth","overflow","overflowAnchor","overflowBlock","overflowClipMargin","overflowInline","overflowWrap","overflowX","overflowY","overlay","overrideColors","overscrollBehavior","overscrollBehaviorBlock","overscrollBehaviorInline","overscrollBehaviorX","overscrollBehaviorY","pad","padding","paddingBlock","paddingBlockEnd","paddingBlockStart","paddingBottom","paddingInline","paddingInlineEnd","paddingInlineStart","paddingLeft","paddingRight","paddingTop","page","pageBreakAfter","pageBreakBefore","pageBreakInside","pageMarginSafety","pageOrientation","paintOrder","perspective","perspectiveOrigin","placeContent","placeItems","placeSelf","pointerEvents","position","positionAnchor","positionArea","positionTry","positionTryFallbacks","positionTryOrder","positionVisibility","prefix","printColorAdjust","quotes","r","range","readingFlow","readingOrder","resize","result","right","rotate","rowGap","rowRule","rowRuleBreak","rowRuleColor","rowRuleInset","rowRuleInsetCap","rowRuleInsetCapEnd","rowRuleInsetCapStart","rowRuleInsetEnd","rowRuleInsetJunction","rowRuleInsetJunctionEnd","rowRuleInsetJunctionStart","rowRuleInsetStart","rowRuleStyle","rowRuleVisibilityItems","rowRuleWidth","rubyAlign","rubyOverhang","rubyPosition","rule","ruleBreak","ruleColor","ruleInset","ruleInsetCap","ruleInsetEnd","ruleInsetJunction","ruleInsetStart","ruleOverlap","ruleStyle","ruleVisibilityItems","ruleWidth","rx","ry","scale","scrollBehavior","scrollInitialTarget","scrollMargin","scrollMarginBlock","scrollMarginBlockEnd","scrollMarginBlockStart","scrollMarginBottom","scrollMarginInline","scrollMarginInlineEnd","scrollMarginInlineStart","scrollMarginLeft","scrollMarginRight","scrollMarginTop","scrollMarkerGroup","scrollPadding","scrollPaddingBlock","scrollPaddingBlockEnd","scrollPaddingBlockStart","scrollPaddingBottom","scrollPaddingInline","scrollPaddingInlineEnd","scrollPaddingInlineStart","scrollPaddingLeft","scrollPaddingRight","scrollPaddingTop","scrollSnapAlign","scrollSnapStop","scrollSnapType","scrollTargetGroup","scrollTimeline","scrollTimelineAxis","scrollTimelineName","scrollbarColor","scrollbarGutter","scrollbarWidth","shapeImageThreshold","shapeMargin","shapeOutside","shapeRendering","size","sizeAdjust","speak","speakAs","src","stopColor","stopOpacity","stroke","strokeDasharray","strokeDashoffset","strokeLinecap","strokeLinejoin","strokeMiterlimit","strokeOpacity","strokeWidth","suffix","symbols","syntax","system","tabSize","tableLayout","textAlign","textAlignLast","textAnchor","textAutospace","textBox","textBoxEdge","textBoxTrim","textCombineUpright","textDecoration","textDecorationColor","textDecorationLine","textDecorationSkipInk","textDecorationStyle","textDecorationThickness","textEmphasis","textEmphasisColor","textEmphasisPosition","textEmphasisStyle","textFit","textIndent","textJustify","textOrientation","textOverflow","textRendering","textShadow","textSizeAdjust","textSpacingTrim","textTransform","textUnderlineOffset","textUnderlinePosition","textWrap","textWrapMode","textWrapStyle","timelineScope","timelineTrigger","timelineTriggerActivationRange","timelineTriggerActivationRangeEnd","timelineTriggerActivationRangeStart","timelineTriggerActiveRange","timelineTriggerActiveRangeEnd","timelineTriggerActiveRangeStart","timelineTriggerName","timelineTriggerSource","top","touchAction","transform","transformBox","transformOrigin","transformStyle","transition","transitionBehavior","transitionDelay","transitionDuration","transitionProperty","transitionTimingFunction","translate","triggerScope","types","unicodeBidi","unicodeRange","userSelect","vectorEffect","verticalAlign","viewTimeline","viewTimelineAxis","viewTimelineInset","viewTimelineName","viewTransitionClass","viewTransitionGroup","viewTransitionName","viewTransitionScope","visibility","webkitAlignContent","webkitAlignItems","webkitAlignSelf","webkitAnimation","webkitAnimationDelay","webkitAnimationDirection","webkitAnimationDuration","webkitAnimationFillMode","webkitAnimationIterationCount","webkitAnimationName","webkitAnimationPlayState","webkitAnimationTimingFunction","webkitAppRegion","webkitAppearance","webkitBackfaceVisibility","webkitBackgroundClip","webkitBackgroundOrigin","webkitBackgroundSize","webkitBorderAfter","webkitBorderAfterColor","webkitBorderAfterStyle","webkitBorderAfterWidth","webkitBorderBefore","webkitBorderBeforeColor","webkitBorderBeforeStyle","webkitBorderBeforeWidth","webkitBorderBottomLeftRadius","webkitBorderBottomRightRadius","webkitBorderEnd","webkitBorderEndColor","webkitBorderEndStyle","webkitBorderEndWidth","webkitBorderHorizontalSpacing","webkitBorderImage","webkitBorderRadius","webkitBorderStart","webkitBorderStartColor","webkitBorderStartStyle","webkitBorderStartWidth","webkitBorderTopLeftRadius","webkitBorderTopRightRadius","webkitBorderVerticalSpacing","webkitBoxAlign","webkitBoxDecorationBreak","webkitBoxDirection","webkitBoxFlex","webkitBoxOrdinalGroup","webkitBoxOrient","webkitBoxPack","webkitBoxReflect","webkitBoxShadow","webkitBoxSizing","webkitClipPath","webkitColumnBreakAfter","webkitColumnBreakBefore","webkitColumnBreakInside","webkitColumnCount","webkitColumnGap","webkitColumnRule","webkitColumnRuleColor","webkitColumnRuleStyle","webkitColumnRuleWidth","webkitColumnSpan","webkitColumnWidth","webkitColumns","webkitFilter","webkitFlex","webkitFlexBasis","webkitFlexDirection","webkitFlexFlow","webkitFlexGrow","webkitFlexShrink","webkitFlexWrap","webkitFontFeatureSettings","webkitFontSmoothing","webkitHyphenateCharacter","webkitJustifyContent","webkitLineBreak","webkitLineClamp","webkitLocale","webkitLogicalHeight","webkitLogicalWidth","webkitMarginAfter","webkitMarginBefore","webkitMarginEnd","webkitMarginStart","webkitMask","webkitMaskBoxImage","webkitMaskBoxImageOutset","webkitMaskBoxImageRepeat","webkitMaskBoxImageSlice","webkitMaskBoxImageSource","webkitMaskBoxImageWidth","webkitMaskClip","webkitMaskComposite","webkitMaskImage","webkitMaskOrigin","webkitMaskPosition","webkitMaskPositionX","webkitMaskPositionY","webkitMaskRepeat","webkitMaskSize","webkitMaxLogicalHeight","webkitMaxLogicalWidth","webkitMinLogicalHeight","webkitMinLogicalWidth","webkitOpacity","webkitOrder","webkitPaddingAfter","webkitPaddingBefore","webkitPaddingEnd","webkitPaddingStart","webkitPerspective","webkitPerspectiveOrigin","webkitPerspectiveOriginX","webkitPerspectiveOriginY","webkitPrintColorAdjust","webkitRtlOrdering","webkitRubyPosition","webkitShapeImageThreshold","webkitShapeMargin","webkitShapeOutside","webkitTapHighlightColor","webkitTextCombine","webkitTextDecorationsInEffect","webkitTextEmphasis","webkitTextEmphasisColor","webkitTextEmphasisPosition","webkitTextEmphasisStyle","webkitTextFillColor","webkitTextOrientation","webkitTextSecurity","webkitTextSizeAdjust","webkitTextStroke","webkitTextStrokeColor","webkitTextStrokeWidth","webkitTransform","webkitTransformOrigin","webkitTransformOriginX","webkitTransformOriginY","webkitTransformOriginZ","webkitTransformStyle","webkitTransition","webkitTransitionDelay","webkitTransitionDuration","webkitTransitionProperty","webkitTransitionTimingFunction","webkitUserDrag","webkitUserModify","webkitUserSelect","webkitWritingMode","whiteSpace","whiteSpaceCollapse","widows","width","willChange","wordBreak","wordSpacing","wordWrap","writingMode","x","y","zIndex","zoom"];

  const __cssMaps = new WeakMap();
  // Объявление → его карта как написано: сокращения — сокращениями. Каскаду
  // она нужна, чтобы `padding: var(--p)` раскладывался после подстановки,
  // а не до неё.
  const __declRaw = new WeakMap();
  // Методы и `length` живут на прототипе, а собственными свойствами объявления
  // идут имена свойств CSS — все семьсот три, в порядке браузера. У нас было
  // наоборот: методы собственными, имён не было вовсе, и перечисление стиля
  // выглядело как что угодно, только не как браузер.
  // Построитель у объявления один — `__inlineStyleProto`. Раньше их было два,
  // и прототип у правила, атрибута и вычисленного стиля общий: чей построитель
  // успевал позже, того и члены, а половина работы первого пропадала. Отсюда
  // и брались нулевая длина у правила, и `item` с именами не из того набора.
  const __shapeStyleProto = () => __inlineStyleProto();

  // Во что браузер разворачивает сокращённые записи. `style.length` считает
  // длинные свойства, а не написанные: у `border: none` их семнадцать, у
  // `font` — девятнадцать. Снято с Chrome 151 перечислением самого объявления.
  const CSS_LONGHANDS = {
    'margin': ['margin-top','margin-right','margin-bottom','margin-left'],
    'padding': ['padding-top','padding-right','padding-bottom','padding-left'],
    'border': ['border-top-width','border-right-width','border-bottom-width','border-left-width','border-top-style','border-right-style','border-bottom-style','border-left-style','border-top-color','border-right-color','border-bottom-color','border-left-color','border-image-source','border-image-slice','border-image-width','border-image-outset','border-image-repeat'],
    'border-width': ['border-top-width','border-right-width','border-bottom-width','border-left-width'],
    'border-style': ['border-top-style','border-right-style','border-bottom-style','border-left-style'],
    'border-color': ['border-top-color','border-right-color','border-bottom-color','border-left-color'],
    'border-image': ['border-image-source','border-image-slice','border-image-width','border-image-outset','border-image-repeat'],
    'border-radius': ['border-top-left-radius','border-top-right-radius','border-bottom-right-radius','border-bottom-left-radius'],
    'background': ['background-image','background-position-x','background-position-y','background-size','background-repeat','background-attachment','background-origin','background-clip','background-color'],
    'background-position': ['background-position-x','background-position-y'],
    'font': ['font-style','font-variant-caps','font-variant-ligatures','font-variant-numeric','font-variant-east-asian','font-variant-alternates','font-size-adjust','font-language-override','font-kerning','font-optical-sizing','font-feature-settings','font-variation-settings','font-variant-position','font-variant-emoji','font-weight','font-stretch','font-size','line-height','font-family'],
    'flex': ['flex-grow','flex-shrink','flex-basis'],
    'flex-flow': ['flex-direction','flex-wrap'],
    'overflow': ['overflow-x','overflow-y'],
    'inset': ['top','right','bottom','left'],
    'gap': ['row-gap','column-gap'],
    'outline': ['outline-color','outline-style','outline-width'],
    'grid-area': ['grid-row-start','grid-column-start','grid-row-end','grid-column-end'],
    'grid-template': ['grid-template-rows','grid-template-columns','grid-template-areas'],
    'transition': ['transition-behavior','transition-duration','transition-timing-function','transition-delay','transition-property'],
    'animation': ['animation-duration','animation-timing-function','animation-delay','animation-iteration-count','animation-direction','animation-fill-mode','animation-play-state','animation-name','animation-timeline','animation-range-start','animation-range-end'],
    'place-content': ['align-content','justify-content'],
    'place-items': ['align-items','justify-items'],
    'text-decoration': ['text-decoration-line','text-decoration-thickness','text-decoration-style','text-decoration-color'],
    'list-style': ['list-style-position','list-style-image','list-style-type'],
    'mask': ['mask-image','-webkit-mask-position-x','-webkit-mask-position-y','mask-size','mask-repeat','mask-origin','mask-clip','mask-composite','mask-mode'],
    'columns': ['column-width','column-count','column-height','column-wrap'],
  };
  // Сокращение браузер собирает обратно, когда может, — но `border`, у которого
  // все составляющие остались начальными, он собрать не может: отличить
  // «задано начальным» от «не задано» нечем, и он печатает длинные. Проверено
  // на одиннадцати значениях: разворачиваются ровно `none` и
  // `medium none currentcolor`, а `0`, `solid`, `red`, `1px solid red` — нет.
  const BORDER_INITIAL = { width: 'medium', style: 'none', color: 'currentcolor' };
  const __borderParts = (v) => {
    const out = { width: null, style: null, color: null };
    for (const tok of String(v).trim().split(/\s+/)) {
      const t = tok.toLowerCase();
      if (/^(none|hidden|dotted|dashed|solid|double|groove|ridge|inset|outset)$/.test(t)) out.style = t;
      else if (/^(thin|medium|thick)$/.test(t) || /^-?[\d.]+(px|em|rem|pt|%)?$/.test(t)) out.width = t;
      else out.color = t;
    }
    return out;
  };
  const __borderAllInitial = (v) => {
    const p = __borderParts(v);
    return (p.width || BORDER_INITIAL.width) === BORDER_INITIAL.width
        && (p.style || BORDER_INITIAL.style) === BORDER_INITIAL.style
        && (p.color || BORDER_INITIAL.color) === BORDER_INITIAL.color;
  };
  /// Пары «имя: значение» на печать: то же, что в объявлении, но с раскрытым
  /// `border`, если раскрыть его пришлось.
  // Четыре стороны, свёрнутые как у браузера: одно значение, если все равны,
  // два — если совпадают противоположные, и так далее.
  const __cssFour = (t, r, b, l) => {
    if (t === r && r === b && b === l) return t;
    if (t === b && r === l) return t + ' ' + r;
    if (r === l) return t + ' ' + r + ' ' + b;
    return t + ' ' + r + ' ' + b + ' ' + l;
  };

  // Семейства, которые браузер собирает обратно из длинных имён.
  const __CSS_BOX_FAMILIES = [
    ['margin', ['margin-top', 'margin-right', 'margin-bottom', 'margin-left']],
    ['padding', ['padding-top', 'padding-right', 'padding-bottom', 'padding-left']],
    ['border-width', ['border-top-width', 'border-right-width', 'border-bottom-width', 'border-left-width']],
    ['border-style', ['border-top-style', 'border-right-style', 'border-bottom-style', 'border-left-style']],
    ['border-color', ['border-top-color', 'border-right-color', 'border-bottom-color', 'border-left-color']],
  ];

  /// Объявления так, как их печатает браузер. Он держит длинные свойства, а
  /// сокращение собирает при печати — поэтому `padding: 1px` с отдельным
  /// `padding-left: 9px` выходит одной записью `padding: 1px 1px 1px 9px`, а
  /// `border` с перебитой стороной распадается на составляющие. Мы печатали
  /// написанное автором, и правило расходилось с браузерным.
  // Набор имён с `!important` живёт при карте объявления: карта строится
  // заново при каждой правке атрибута, и набор вместе с ней.
  const __cssImp = (m) => {
    if (!m.__ptImp) { try { Object.defineProperty(m, '__ptImp', { value: new Set(), enumerable: false, configurable: true }); } catch (e) { return new Set(); } }
    return m.__ptImp;
  };
  const __cssImportantIn = (v) => typeof v === 'string' && /!\s*important\s*$/i.test(v);
  // Точное значение — рядом с напечатанным: браузер хранит число как разобрал,
  // а шестью знаками только печатает. Раскладка и масштаб текста считают по
  // точному; страница читает напечатанное.
  const __cssPrecise = (m) => {
    if (!m.__ptPrecise) { try { Object.defineProperty(m, '__ptPrecise', { value: new Map(), enumerable: false, configurable: true }); } catch (e) { return new Map(); } }
    return m.__ptPrecise;
  };
  const __cssStore = (m, k, v) => {
    const raw = __cssValueRaw(k, v);
    let shown = raw;
    if (!((k.charCodeAt(0) === 45 && k.charCodeAt(1) === 45) || k === 'unicode-range')) { try { shown = __cssNumbers(raw); } catch (e) {} }
    m.set(k, shown);
    const pm = __cssPrecise(m);
    if (shown !== raw) pm.set(k, raw); else pm.delete(k);
  };
  const __cssDrop = (m, k) => { m.delete(k); if (m.__ptImp) m.__ptImp.delete(k); if (m.__ptPrecise) m.__ptPrecise.delete(k); };
  const __cssPreciseGet = (m, k) => (m.__ptPrecise && m.__ptPrecise.has(k) ? m.__ptPrecise.get(k) : m.get(k));
  const __styleText = (m) => {
    const imp = m.__ptImp;
    const important = (k) => {
      if (!imp || !imp.size) return false;
      if (imp.has(k)) return true;
      for (const sh of imp) if ((CSS_LONGHANDS[sh] || []).includes(k)) return true;
      return false;
    };
    return __styleEntries(m).map(([k, v]) => `${k}: ${v}${important(k) ? ' !important' : ''};`).join(' ');
  };
  const __styleEntries = (m) => {
    // Какие длинные имена написаны отдельно: только из-за них сокращение
    // разбирают.
    // Что написано отдельно — с учётом того, что и само написанное бывает
    // сокращением: `border` разбирают и тогда, когда рядом стоит
    // `border-width`, а не только `border-top-width`.
    const written = new Set();
    for (const k of m.keys()) {
      written.add(k);
      for (const n of (CSS_LONGHANDS[k] || [])) written.add(n);
    }
    const order = [];
    const seen = new Map();
    const put = (k, v) => {
      if (seen.has(k)) order[seen.get(k)] = null;
      seen.set(k, order.length);
      order.push([k, v]);
    };
    for (const [k, v] of m) {
      if (k === 'border' && __borderAllInitial(v)) {
        put('border-width', 'medium'); put('border-style', 'none');
        put('border-color', 'currentcolor'); put('border-image', 'none');
        continue;
      }
      const list = CSS_LONGHANDS[k];
      const overridden = list && list.some((n) => {
        if (!written.has(n)) return false;
        // Своё собственное разложение переписью не считается.
        return ![...m.keys()].every((other) => other === k
          || !(other === n || (CSS_LONGHANDS[other] || []).includes(n)));
      });
      const pairs = overridden && typeof __ptExpand === 'function' ? __ptExpand(k, v) : null;
      if (pairs && pairs.length) {
        for (const [lk, lv] of pairs) put(lk, lv);
        if (k === 'border') put('border-image', 'none');
        continue;
      }
      put(k, v);
    }
    let live = order.filter(Boolean);
    // Собрать обратно: сокращение встаёт на место первой своей части.
    for (const [short, parts] of __CSS_BOX_FAMILIES) {
      const at = parts.map((n) => live.findIndex(([k]) => k === short || k === n));
      if (at.some((i) => i < 0)) continue;
      const vals = parts.map((n) => (live.find(([k]) => k === n) || [])[1]);
      if (vals.some((x) => x == null)) continue;
      const first = Math.min(...at);
      const merged = [short, __cssFour(vals[0], vals[1], vals[2], vals[3])];
      live = live.map((e, i) => (i === first ? merged : (parts.includes(e[0]) ? null : e)))
        .filter(Boolean);
    }
    return live;
  };

  /// Значение длинного свойства, написанного сокращением. Браузер хранит
  /// разложенное: после `style.border = '1px solid'` он отвечает `1px` на
  /// `style.borderTopWidth`, а мы держали только саму запись и отвечали
  /// пустотой — вместе с ней пропадала и рамка из раскладки.
  // Обратный указатель: в каких сокращениях встречается это длинное
  // свойство. Без него поиск шёл перебором всей карты — у вычисленного стиля
  // это четыре с половиной сотни записей на каждое спрошенное имя, и перебор
  // стиля целиком стоил лишних две с половиной миллисекунды.
  let __SHORTS_OF = null;
  const __shortsOf = (key) => {
    if (!__SHORTS_OF) {
      __SHORTS_OF = Object.create(null);
      for (const short of Object.keys(CSS_LONGHANDS)) {
        for (const long of CSS_LONGHANDS[short]) {
          (__SHORTS_OF[long] || (__SHORTS_OF[long] = [])).push(short);
        }
      }
    }
    return __SHORTS_OF[key];
  };

  const __longhandFrom = (m, key) => {
    const shorts = __shortsOf(key);
    if (shorts) {
      for (const short of shorts) {
        const value = m.get(short);
        if (value == null) continue;
        const pairs = typeof __ptExpand === 'function' ? __ptExpand(short, value) : null;
        if (!pairs) continue;
        for (const [k, v] of pairs) if (k === key) return v;
      }
    }
    // И наоборот: сокращение, собранное из длинных. `border: 1px solid`
    // отвечает `solid` на `borderStyle`, потому что все четыре стороны
    // одинаковы; разнобой браузер сокращением не печатает.
    const own = CSS_LONGHANDS[key];
    if (own && !m.has(key)) {
      let same = null;
      for (const n of own) {
        const v = m.get(n) || __longhandFrom(m, n);
        if (!v) return '';
        if (same == null) same = v;
        else if (same !== v) return '';
      }
      if (same != null) return same;
    }
    return '';
  };

  /// Имена, которые перечисляет объявление: сокращения раскрыты, порядок как у
  /// браузера — в порядке появления, без повторов.
  const __styleNames = (m) => {
    const out = [];
    for (const k of m.keys()) for (const n of (CSS_LONGHANDS[k] || [k])) if (!out.includes(n)) out.push(n);
    return out;
  };

  function __cssDeclaration(map) {
    const dash = (p) => String(p).replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
    const target = Object.create(__shapeStyleProto(__styleProto()));
    __cssMaps.set(target, map);
    // Имена свойств — собственные, как в браузере, и в его порядке.
    for (const name of CSS_PROPS) {
      const key = dash(name).toLowerCase();
      Object.defineProperty(target, name, {
        get() { return map.get(key) || __longhandFrom(map, key); },
        set(v) { if (v === '' || v == null) map.delete(key); else map.set(key, __cssValue(key, v)); },
        enumerable: true, configurable: true,
      });
    }
    const px = __ptProxy(target, {
      get: (t, p) => {
        if (typeof p === 'string' && !(p in t)) return map.get(dash(p).toLowerCase()) || '';
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
      set: (t, p, v) => {
        if (typeof p === 'string' && !(p in t)) {
          const k = dash(p).toLowerCase();
          if (v === '' || v == null) map.delete(k); else map.set(k, __cssValue(k, v));
          return true;
        }
        t[p] = v; return true;
      },
    });
    __declRaw.set(px, () => map);
    return px;
  }

  const __ruleListProto = {
    get [Symbol.toStringTag]() { return 'CSSRuleList'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __cssRuleList(arr) {
    const list = Object.create(__link('CSSRuleList', __ruleListProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }

  const __mediaListProto = {
    get [Symbol.toStringTag]() { return 'MediaList'; },
    get mediaText() { return this.__ptMedia.join(', '); },
    set mediaText(v) { this.__ptMedia = String(v).split(',').map((s) => s.trim()).filter(Boolean); },
    get length() { return this.__ptMedia.length; },
    item(i) { return this.__ptMedia[i] != null ? this.__ptMedia[i] : null; },
    appendMedium(m) { if (!this.__ptMedia.includes(String(m))) this.__ptMedia.push(String(m)); },
    deleteMedium(m) { this.__ptMedia = this.__ptMedia.filter((x) => x !== String(m)); },
    toString() { return this.mediaText; },
  };
  function __mediaList(text) {
    const m = Object.create(__link('MediaList', __mediaListProto));
    Object.defineProperty(m, '__ptMedia', {
      value: String(text || '').split(',').map((s) => s.trim()).filter(Boolean),
      writable: true, enumerable: false,
    });
    return m;
  }

  // Правила. Числа типов — те же, что у CSSRule в браузере.
  const RULE_TYPE = { style: 1, charset: 2, import: 3, media: 4, 'font-face': 5,
                      page: 6, keyframes: 7, keyframe: 8, supports: 12 };
  const __ruleProtos = new Map();
  const __ruleProto = (name) => {
    let p = __ruleProtos.get(name);
    if (p) return p;
    const base = globalThis[name] && globalThis[name].prototype;
    p = base || Object.prototype;
    try {
      if (base && !Object.getOwnPropertyDescriptor(base, Symbol.toStringTag)) {
        Object.defineProperty(base, Symbol.toStringTag, { value: name, configurable: true });
      }
    } catch (e) {}
    __ruleProtos.set(name, p);
    return p;
  };
  // Правило с потомками браузер печатает в несколько строк, по строке на
  // потомка с отступом в два пробела. `@keyframes` при этом оставляет пробел
  // после открывающей скобки, а `@media` — нет; так в Chrome, и так здесь.
  const __cssGroup = (prelude, kids, pad) => prelude + ' {' + (pad ? ' ' : '') + '\n'
    + kids.map((k) => '  ' + String(k.cssText).replace(/\n/g, '\n  ')).join('\n')
    + '\n}';

  function __makeRule(parsed, sheet, parent) {
    const prelude = parsed.prelude || '';
    const at = prelude.charCodeAt(0) === 64 ? prelude.split(/[\s({]/)[0].toLowerCase() : '';
    const own = (r, props) => { for (const k of Object.keys(props)) Object.defineProperty(r, k, { value: props[k], enumerable: true, configurable: true }); return r; };
    const common = (r, type) => own(r, {
      type, parentStyleSheet: sheet, parentRule: parent || null,
    });

    if (at === '@import') {
      const href = (/url\(\s*["']?([^"')]*)["']?\s*\)|["']([^"']*)["']/.exec(prelude) || [])
        .slice(1).find((x) => x !== undefined) || '';
      const r = common(Object.create(__ruleProto('CSSImportRule')), RULE_TYPE.import);
      return own(r, { href, layerName: null, supportsText: null, styleSheet: null,
                      media: __mediaList(''), cssText: '@import url("' + href + '");' });
    }
    if (at === '@media' || at === '@supports') {
      const name = at === '@media' ? 'CSSMediaRule' : 'CSSSupportsRule';
      const r = common(Object.create(__ruleProto(name)), at === '@media' ? RULE_TYPE.media : RULE_TYPE.supports);
      const cond = __cssPrelude(prelude.slice(at.length).trim());
      const kids = __cssParse(parsed.body || '').map((p) => __makeRule(p, sheet, r)).filter(Boolean);
      own(r, { cssRules: __cssRuleList(kids), conditionText: cond });
      if (at === '@media') own(r, { media: __mediaList(cond) });
      return own(r, { cssText: __cssGroup(at + ' ' + cond, kids, false) });
    }
    if (at === '@keyframes' || at === '@-webkit-keyframes') {
      const r = common(Object.create(__ruleProto('CSSKeyframesRule')), RULE_TYPE.keyframes);
      const kids = __cssParse(parsed.body || '').map((p) => {
        const k = common(Object.create(__ruleProto('CSSKeyframeRule')), RULE_TYPE.keyframe);
        const decls = __cssDecls(p.body || '');
        return own(k, { keyText: __cssPrelude(p.prelude), style: __cssDeclaration(decls),
                        cssText: __cssPrelude(p.prelude) + ' { '
                          + __styleEntries(decls).map(([a2, b2]) => a2 + ': ' + b2 + ';').join(' ') + ' }' });
      });
      const name = prelude.slice(at.length).trim();
      return own(r, { name, length: kids.length, cssRules: __cssRuleList(kids),
                      appendRule() {}, deleteRule() {}, findRule() { return null; },
                      cssText: __cssGroup('@keyframes ' + name, kids, true) });
    }
    if (at === '@font-face') {
      const r = common(Object.create(__ruleProto('CSSFontFaceRule')), RULE_TYPE['font-face']);
      const decls = __cssDecls(parsed.body || '');
      return own(r, { style: __cssDeclaration(decls),
                      cssText: '@font-face { '
                        + __styleEntries(decls).map(([a2, b2]) => a2 + ': ' + b2 + ';').join(' ') + ' }' });
    }
    if (at) {
      // `@charset` браузер в перечень правил не кладёт вовсе — он читает его и
      // забывает. У нас он торчал лишней записью в каждой таблице, которая с
      // него начинается.
      if (/^@charset\b/i.test(prelude)) return null;
      const r = common(Object.create(__ruleProto('CSSRule')), RULE_TYPE.charset);
      return own(r, { cssText: prelude + (parsed.statement ? ';' : ' { }') });
    }
    const r = common(Object.create(__ruleProto('CSSStyleRule')), RULE_TYPE.style);
    const decls = __cssDecls(parsed.body || '');
    const sel = __cssSelector(prelude);
    const body = __styleEntries(decls).map(([k, v]) => k + ': ' + v + ';').join(' ');
    own(r, { selectorText: sel });
    // Объявление правила — семьсот свойств на объекте — строится, только
    // когда его попросят. Строить его на каждое из тысяч правил стоило
    // восьмисот миллисекунд на таблицу: страница с двумя крупными таблицами
    // запускала первый скрипт на две секунды позже браузера. Каскаду оно не
    // нужно — он читает карту объявлений напрямую.
    Object.defineProperty(r, 'style', {
      get() {
        const d = __cssDeclaration(decls);
        Object.defineProperty(this, 'style', { value: d, enumerable: true, configurable: true });
        return d;
      },
      enumerable: true, configurable: true,
    });
    Object.defineProperty(r, '__ptDecls', { value: decls, enumerable: false, configurable: true });
    return own(r, { cssRules: __cssRuleList([]), insertRule() { return 0; }, deleteRule() {},
                    cssText: sel + ' { ' + (body ? body + ' ' : '') + '}' });
  }

  const __sheetProto = {
    get [Symbol.toStringTag]() { return 'CSSStyleSheet'; },
    get rules() { return this.cssRules; },
    insertRule(text, index) {
      const parsed = __cssParse(String(text))[0];
      if (!parsed) return 0;
      const arr = [...this.cssRules];
      const at = index === undefined ? 0 : Math.min(index | 0, arr.length);
      arr.splice(at, 0, __makeRule(parsed, this, null));
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(arr), enumerable: true, configurable: true });
      return at;
    },
    deleteRule(index) {
      const arr = [...this.cssRules];
      arr.splice(index | 0, 1);
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(arr), enumerable: true, configurable: true });
    },
    addRule(sel, decl, index) { return this.insertRule(sel + ' { ' + (decl || '') + ' }', index), -1; },
    removeRule(index) { this.deleteRule(index); },
    replaceSync(text) {
      const rules = __cssParse(String(text)).map((p) => __makeRule(p, this, null)).filter(Boolean);
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(rules), enumerable: true, configurable: true });
    },
    replace(text) { this.replaceSync(text); return Promise.resolve(this); },
  };
  // Таблица живёт на своём элементе: страницы сравнивают
  // `document.styleSheets[0] === document.styleSheets[0]`, и правила
  // пересобираются только когда сменился текст.
  globalThis.__pt_sheetFor = (owner) => __sheetFor(owner);
  function __sheetFor(owner) {
    const proto = __link('CSSStyleSheet', __sheetProto);
    const text = owner.__ptLocal === 'style'
      ? String(owner.textContent || '')
      : String(owner.__ptSheetText || '');
    let sheet = owner.__ptSheet;
    if (!sheet) {
      sheet = Object.create(proto);
      Object.defineProperty(owner, '__ptSheet', { value: sheet, writable: true, enumerable: false });
      const href = owner.__ptLocal === 'link' ? (owner.href || null) : null;
      Object.defineProperty(sheet, 'ownerNode', { value: owner, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'href', { value: href, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'type', { value: 'text/css', enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'disabled', { value: false, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'title', { value: __ptGetA(owner, 'title'), enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'media', { value: __mediaList(__ptGetA(owner, 'media') || ''), enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'parentStyleSheet', { value: null, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'ownerRule', { value: null, enumerable: true, configurable: true });
    }
    if (sheet.__ptText !== text) {
      Object.defineProperty(sheet, '__ptText', { value: text, writable: true, enumerable: false, configurable: true });
      const rules = __cssParse(text).map((p) => __makeRule(p, sheet, null)).filter(Boolean);
      Object.defineProperty(sheet, 'cssRules', { value: __cssRuleList(rules), enumerable: true, configurable: true });
    }
    return sheet;
  }
  const __sheetListProto = {
    get [Symbol.toStringTag]() { return 'StyleSheetList'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __styleSheetList(owners) {
    const list = Object.create(__link('StyleSheetList', __sheetListProto));
    for (let i = 0; i < owners.length; i++) list[i] = __sheetFor(owners[i]);
    Object.defineProperty(list, '__ptLen', { value: owners.length, enumerable: false, configurable: true });
    return list;
  }

  function makeDataset(el) {
    const target = {};
    for (const k of el.getAttributeNames()) if (k.startsWith('data-'))
      target[camel(k.slice(5))] = __ptGetA(el, k);
    return __ptProxy(target, {
      get: (t, p) => __ptGetA(el, 'data-' + dash(String(p))) ?? undefined,
      set: (t, p, v) => { __ptSetA(el, 'data-' + dash(String(p)), v); return true; },
      has: (t, p) => __ptHasA(el, 'data-' + dash(String(p))),
    });
  }
  const camel = (s) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  const dash = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
  // `el.style` и атрибут `style` — два вида на одно и то же. У нас это были два
  // независимых хранилища: `setAttribute('style','width:300px')` не доходил до
  // `el.style.width`, а `el.style.width = …` не доходил до атрибута. Отсюда же
  // и кадр, который не знал своего размера: раскладка читает одно, страница
  // пишет другое.
  // Инлайновый стиль тоже CSSStyleDeclaration: `el.style` в браузере и
  // `getComputedStyle(el)` — один интерфейс, и сборщик читает его имя.
  const __styleProto = () => {
    const proto = (globalThis.CSSStyleDeclaration && CSSStyleDeclaration.prototype) || Object.prototype;
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'CSSStyleDeclaration', configurable: true });
      }
    } catch (e) {}
    return proto;
  };
  const __cssReaders = new WeakMap();
  // Прототип инлайнового объявления: те же десять членов, что у браузера.
  const __inlineStyleProto = () => {
    const proto = __styleProto();
    if (proto.__ptInlineShaped) return proto;
    try { Object.defineProperty(proto, '__ptInlineShaped', { value: true }); } catch (e) {}
    // Объявление бывает двух видов: инлайновое (за ним атрибут элемента) и
    // правило таблицы (за ним карта разобранных объявлений). Члены у них
    // общие — они лежат на одном прототипе, — поэтому здесь понимаются оба.
    // Пока понимался один, порядок сборки решал: если первым успевало
    // правило, у инлайнового пропадали чтения, а если первым инлайновое —
    // у правила выходила нулевая длина, и каскад не брал ни одного
    // объявления.
    const st = (o) => {
      const own = __cssReaders.get(o);
      if (own) return own;
      const map = __cssMaps.get(o);
      if (!map) return null;
      return { read: () => map, write: () => {}, computed: false, map, el: null };
    };
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const def = (name, value) => {
      const m = ({ [name](...a) { return value.apply(this, a); } })[name];
      try { Object.defineProperty(m, 'length', { value: value.length, configurable: true }); } catch (e) {}
      try { Object.defineProperty(proto, name, { value: nat(m, name), writable: true, enumerable: true, configurable: true }); } catch (e) {}
    };
    const acc = (name, get, set) => {
      try { Object.defineProperty(proto, name, { get: nat(get, 'get ' + name), set: set ? nat(set, 'set ' + name) : undefined, enumerable: true, configurable: true }); } catch (e) {}
    };
    def('getPropertyValue', function getPropertyValue(p) {
      const s = st(this); if (!s) return '';
      const k = __cssKey(p);
      const m = s.computed ? s.map : s.read();
      // Имена с приставкой поставщика спрашивают и с дефисом впереди, а
      // длинное свойство может быть записано сокращением: `border-top-width`
      // отвечает из `border`. А `-epub-…` — просто другое имя: у вычисленного
      // стиля `-epub-word-break` отвечает тем же, чем `word-break`.
      const alias = s.computed ? EPUB_ALIAS[k] : null;
      if (alias) return m.get(alias) || __longhandFrom(m, alias) || '';
      return m.get(k) || (k.charCodeAt(0) === 45 ? m.get(k.slice(1)) || '' : '')
        || __longhandFrom(m, k);
    });
    def('getPropertyPriority', function getPropertyPriority(p) {
      const s = st(this); if (!s || s.computed) return '';
      const m = s.read(), k = __cssKey(p), imp = m.__ptImp;
      if (!imp || !imp.size) return '';
      if (imp.has(k)) return 'important';
      for (const sh of imp) if ((CSS_LONGHANDS[sh] || []).includes(k)) return 'important';
      return '';
    });
    def('setProperty', function setProperty(p, v, prio) {
      const s = st(this); if (!s) return;
      if (s.computed) throw new TypeError('Cannot modify computed style');
      // Приоритет — либо пусто, либо `important`; иное браузер молча
      // отвергает вместе со всем вызовом. И `!important` внутри значения —
      // тоже отказ.
      const pr = prio == null ? '' : String(prio).trim().toLowerCase();
      if (pr !== '' && pr !== 'important') return;
      if (__cssImportantIn(v)) return;
      const m = s.read(), k = __cssKey(p);
      // Пустое значение свойство удаляет, а не оставляет пустым. Мы писали
      // `opacity: ` без значения — строки, которой браузер не производит; кадр
      // виджета читает свой `style` десятками тысяч раз и видел именно её.
      if (v === '' || v == null) __cssDrop(m, k);
      else { __cssStore(m, k, v); if (pr === 'important') __cssImp(m).add(k); else __cssImp(m).delete(k); }
      s.write(m);
    });
    def('removeProperty', function removeProperty(p) {
      const s = st(this); if (!s) return '';
      if (s.computed) throw new TypeError('Cannot modify computed style');
      const m = s.read(), k = __cssKey(p), had = m.get(k) || '';
      __cssDrop(m, k); s.write(m); return had;
    });
    def('item', function item(i) {
      const s = st(this); if (!s) return '';
      return s.computed ? (s.names[i] || '') : (__styleNames(s.read())[i] || '');
    });
    acc('length', function length() {
      const s = st(this); if (!s) return 0;
      return s.computed ? s.names.length : __styleNames(s.read()).length;
    });
    acc('parentRule', function parentRule() { return null; });
    acc('cssFloat',
      function cssFloat() { const s = st(this); return s ? (s.read().get('float') || '') : ''; },
      function cssFloat(v) { const s = st(this); if (!s) return; const m = s.read(); m.set('float', String(v)); s.write(m); });
    acc('cssText',
      function cssText() {
        const s = st(this); if (!s) return '';
        // У вычисленного стиля он пуст, как в браузере.
        if (s.computed) return '';
        return __styleText(s.read());
      },
      function cssText(v) {
        const s = st(this); if (!s) return;
        if (s.el && s.el.setAttribute) __ptSetA(s.el, 'style', String(v));
        __markDirty();
      });
    try {
      Object.defineProperty(proto, Symbol.iterator, {
        value: function* () { const s = st(this); if (!s) return; for (const k of (s.computed ? s.names : __styleNames(s.read()))) yield k; },
        writable: true, configurable: true,
      });
    } catch (e) {}
    return proto;
  };

  // Описания семисот с лишним свойств CSS строятся один раз на всех: они
  // ходят за своим объявлением через `this`, и потому одинаковы. Объявление
  // у каждого элемента своё, и когда каждое строило себе семьсот
  // акцессоров заново, одно только чтение `el.style` стоило полмиллисекунды —
  // страница, которая трогает стиль у тысячи узлов, теряла на этом полсекунды.
  // Девять имён с приставкой -epub-: браузер показывает их в списке
  // собственных свойств объявления, но описания у них нет, `in` отвечает
  // «нет», а чтение даёт `undefined`. Так выглядит перехватчик V8 изнутри, и
  // повторить это можно только ловушками: если завести свойства всерьёз,
  // разойдутся и `in`, и описание.
  const EPUB_NAMES = ['epubCaptionSide', 'epubTextCombine', 'epubTextEmphasis',
    'epubTextEmphasisColor', 'epubTextEmphasisStyle', 'epubTextOrientation',
    'epubTextTransform', 'epubWordBreak', 'epubWritingMode'];
  const EPUB_SET = new Set(EPUB_NAMES);
  // Чем каждое из них отвечает на `getPropertyValue('-epub-…')` у вычисленного
  // стиля: это другие имена для обычных свойств.
  const EPUB_ALIAS = {
    '-epub-caption-side': 'caption-side', '-epub-text-combine': 'text-combine-upright',
    '-epub-text-emphasis': 'text-emphasis', '-epub-text-emphasis-color': 'text-emphasis-color',
    '-epub-text-emphasis-style': 'text-emphasis-style', '-epub-text-orientation': 'text-orientation',
    '-epub-text-transform': 'text-transform', '-epub-word-break': 'word-break',
    '-epub-writing-mode': 'writing-mode',
  };
  // Имена вставляются туда же, где они у браузера, — следом за `emptyCells`.
  const __withEpub = (keys) => {
    const at = keys.indexOf('emptyCells');
    if (at < 0) return keys;
    return keys.slice(0, at + 1).concat(EPUB_NAMES, keys.slice(at + 1));
  };
  // Свойства объявления браузер отдаёт значениями, а не акцессорами: в
  // описании `color` лежит `value: "red"`, и ни `get`, ни `set` там нет. У нас
  // они были акцессорами — первое, что видно тому, кто читает описания.
  // Имена свойств CSS — множеством: описание у них одинаковой формы, и
  // спрашивают их тысячами (перебор объявления — тысяча двести имён), так что
  // разбираться, чьё это имя, надо за один поиск, а не через `Reflect`.
  let __CSS_PROP_SET = null;
  const __cssPropSet = () => (__CSS_PROP_SET || (__CSS_PROP_SET = new Set(CSS_PROPS)));
  const __declTraps = (valueOf) => ({
    ownKeys: (t) => __withEpub(Reflect.ownKeys(t)),
    getOwnPropertyDescriptor: (t, p) => {
      if (typeof p === 'string') {
        if (EPUB_SET.has(p)) return undefined;
        if (__cssPropSet().has(p)) {
          return { value: valueOf(t, p), writable: true, enumerable: true, configurable: true };
        }
      }
      return Reflect.getOwnPropertyDescriptor(t, p);
    },
  });

  let __STYLE_DESCS = null;
  const __styleDescs = () => {
    if (__STYLE_DESCS) return __STYLE_DESCS;
    const d = {};
    for (const name of CSS_PROPS) {
      const key = dash(name);
      d[name] = {
        get() {
          const s = __cssReaders.get(this);
          if (!s) return '';
          const m = s.computed ? s.map : s.read();
          return m.get(key) || __longhandFrom(m, key);
        },
        set(v) {
          const s = __cssReaders.get(this);
          if (!s || s.computed) return;
          const m = s.read();
          if (__cssImportantIn(v)) return;
          if (v === '' || v == null) __cssDrop(m, key); else { __cssStore(m, key, v); __cssImp(m).delete(key); }
          s.write(m);
        },
        enumerable: true, configurable: true,
      };
    }
    __STYLE_DESCS = d;
    return d;
  };

  function makeStyle(el) {
    let cachedText = null, cachedMap = new Map();
    const read = () => {
      const text = String((el && el.getAttribute && __ptGetA(el, 'style')) || '');
      if (text === cachedText) return cachedMap;
      const m = new Map();
      for (const part of text.split(';')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        const k = __cssKey(part.slice(0, i));
        let v = part.slice(i + 1).trim();
        // Приоритет хранится рядом со значением, а не в нём: `getPropertyValue`
        // отвечает без `!important`, `getPropertyPriority` — им.
        const im = /!\s*important\s*$/i.exec(v);
        if (im) v = v.slice(0, im.index).trim();
        if (k) { m.set(k, v); if (im) __cssImp(m).add(k); }
      }
      cachedText = text; cachedMap = m;
      return m;
    };
    let indexed = 0;
    // Числовые свойства объявления: у браузера они собственные, как и имена, и
    // перечисляются первыми — у элемента с двумя объявлениями это `0`, `1`, а
    // потом уже `accentColor`. У нас их не было вовсе. Порядок доставать не
    // приходится: целочисленные ключи в JavaScript и так идут впереди.
    const reindex = (names) => {
      for (let i = 0; i < names.length; i++) {
        try { Object.defineProperty(target, String(i), { value: names[i], enumerable: true, configurable: true }); } catch (e) {}
      }
      for (let i = names.length; i < indexed; i++) { try { delete target[String(i)]; } catch (e) {} }
      indexed = names.length;
    };
    const write = (m) => {
      // Точка с запятой в конце обязательна: браузер её ставит.
      const text = __styleText(m);
      cachedText = text; cachedMap = m;
      if (el && el.setAttribute) __ptSetA(el, 'style', text);
      reindex(__styleNames(m));
      __markDirty();
    };
    // Форма как у браузера: методы и `length` — на прототипе, а собственными
    // свойствами объявления идут имена свойств CSS, все семьсот три и в том же
    // порядке. У нас собственными были методы, а имён не было вовсе — и всякий,
    // кто перечисляет стиль (а его перечисляют), видел это сразу.
    const target = Object.create(__inlineStyleProto(), __styleDescs());
    __cssReaders.set(target, { read, write, el });
    reindex(__styleNames(read()));
    const px = __ptProxy(target, {
      ...__declTraps((t, p) => { const m = read(), k = dash(p); return m.get(k) || __longhandFrom(m, k); }),
      get: (t, p) => {
        if (typeof p === 'string' && EPUB_SET.has(p)) return undefined;
        if (typeof p === 'string' && !(p in t)) {
          const m = read(), k = dash(p);
          return m.get(k) || __longhandFrom(m, k);
        }
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
      set: (t, p, v) => {
        if (p === 'cssText') { t.cssText = v; return true; }
        // Через перехватчик — те же правила, что через установщик: пустое
        // значение удаляет свойство. Раньше он писал мимо и оставлял `opacity: `.
        const m = read(), k = dash(String(p));
        // Значение с `!important` через свойство браузер отвергает целиком.
        if (__cssImportantIn(v)) return true;
        if (v === '' || v == null) __cssDrop(m, k); else { __cssStore(m, k, v); __cssImp(m).delete(k); }
        write(m); return true;
      },
    });
    __declRaw.set(px, read);
    return px;
  }

  // ---- tree walking ---------------------------------------------------------
  // Внутри движка нужен массив (concat/filter), наружу — коллекция.
  function __docTags(doc, t) { return doc.documentElement ? __tags(doc.documentElement, t) : []; }
  function __tags(root, t) {
    // По внутреннему имени, не через `tagName`: свой обход не должен ходить
    // через акцессоры, которые страница видит (и может подменить), — иначе
    // один `document.body` оставляет в её ленте десяток чужих чтений.
    const local = String(t).toLowerCase();
    return collect(root, (e) => t === '*' || e.__ptLocal === local);
  }
  function __tagsNS(root, ns, local) {
    const L = String(local), N = ns === null ? null : String(ns);
    return collect(root, (e) => (L === '*' || e.__ptLocal === L || e.localName === L)
      && (N === '*' || (e.namespaceURI || null) === (N === '' ? null : N)));
  }
  function collect(root, pred) {
    const out = []; walk(root, e => { if (pred(e)) out.push(e); });
    out.item = (i) => out[i] || null; return out;
  }
  /// Есть ли у элемента таблица. У `<link>` — только со словом `stylesheet`
  /// в `rel` и с непустым `href`: chess.com держит в разметке
  /// `<link rel="stylesheet" data-href=…>` про запас, и у браузера такой
  /// ссылки в `document.styleSheets` нет, а у нас она была — и счёт таблиц,
  /// который api.js Turnstile отправляет виджету, выходил на одну больше.
  function __ptHasSheet(e) {
    if (e.__ptLocal === 'style') return true;
    if (e.__ptLocal !== 'link') return false;
    const rel = String(__ptGetA(e, 'rel') || '').toLowerCase().split(/[\t\n\f\r ]+/);
    if (rel.indexOf('stylesheet') < 0 || rel.indexOf('alternate') >= 0) return false;
    return !!String(__ptGetA(e, 'href') || '').trim();
  }
  /// Владельцы таблиц в порядке документа.
  function __sheetOwners(root) {
    const own = [];
    const visit = (n) => {
      for (const c of (n.__ptKids || [])) {
        if (c.nodeType !== ELEMENT_NODE) continue;
        if (__ptHasSheet(c)) own.push(c);
        visit(c);
      }
    };
    visit(root);
    return own;
  }

  function firstMatch(root, pred) {
    let found = null; walk(root, e => { if (!found && pred(e)) found = e; }); return found;
  }
  function walk(node, visit) {
    for (const c of node.__ptKids) {
      if (c.nodeType === ELEMENT_NODE) { visit(c); walk(c, visit); }
    }
  }

  // ---- selector engine ------------------------------------------------------
  // Разбор селектора целиком: простые, составные, все четыре комбинатора и
  // псевдоклассы. Прежний движок знал только теги, классы, `#id`, атрибуты и
  // два комбинатора, а псевдокласс читал как имя тега: `:root` искал элемент
  // `<root>`. На chess.com все переменные стоят в `:root { … }` — и ни одна
  // не доходила до страницы, а с ними вся раскладка формы входа.
  const __selCache = new Map();
  const __SEL_NEVER = () => false;

  /// Список селекторов → части верхнего уровня (запятые внутри скобок,
  /// квадратных скобок и кавычек не делят).
  function __selSplit(s) {
    const out = [];
    let depth = 0, q = null, start = 0;
    s = String(s);
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\') { i++; continue; }
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (c === ',' && depth === 0) { out.push(s.slice(start, i)); start = i + 1; }
    }
    out.push(s.slice(start));
    return out.map((x) => x.trim());
  }

  function __selParse(src) {
    let i = 0;
    const s = String(src);
    const ws = () => { const a = i; while (i < s.length && /\s/.test(s[i])) i++; return i > a; };
    const identStart = (c) => c != null && (/[A-Za-z_ -￿-]/.test(c) || c === '\\');
    const ident = () => {
      let out = '';
      while (i < s.length) {
        const c = s[i];
        if (c === '\\') {
          const hex = /^[0-9a-fA-F]{1,6}\s?/.exec(s.slice(i + 1, i + 8));
          if (hex) { out += String.fromCodePoint(parseInt(hex[0], 16) || 0xfffd); i += 1 + hex[0].length; }
          else { out += s[i + 1] || ''; i += 2; }
        } else if (/[\w -￿-]/.test(c)) { out += c; i++; }
        else break;
      }
      return out;
    };
    const fail = () => { throw new SyntaxError('selector'); };
    // Содержимое скобок как строка, с учётом вложенности и кавычек.
    const paren = () => {
      if (s[i] !== '(') fail();
      let depth = 1, q = null; const a = ++i;
      for (; i < s.length; i++) {
        const c = s[i];
        if (c === '\\') { i++; continue; }
        if (q) { if (c === q) q = null; continue; }
        if (c === '"' || c === "'") q = c;
        else if (c === '(') depth++;
        else if (c === ')' && --depth === 0) break;
      }
      if (depth) fail();
      return s.slice(a, i++);
    };
    const compound = () => {
      const tests = [];
      const spec = [0, 0, 0];
      let any = false;
      for (;;) {
        const c = s[i];
        if (c === '*') {
          i++; any = true;
          if (s[i] === '|') { i++; if (s[i] === '*') i++; else { const n = ident().toLowerCase(); spec[2]++; tests.push((e) => e.localName === n); } }
          continue;
        }
        if (c === '|') { i++; continue; }
        if (identStart(c)) {
          if (any || tests.length) break;
          let n = ident();
          if (s[i] === '|' && s[i + 1] !== '=') { i++; if (s[i] === '*') { i++; any = true; continue; } n = ident(); }
          const low = n.toLowerCase();
          spec[2]++; any = true;
          tests.push((e) => e.localName === low || (e.__ptNS && e.__ptNS !== 'http://www.w3.org/1999/xhtml' && e.localName === n));
          continue;
        }
        if (c === '#') { i++; const n = ident(); if (!n) fail(); spec[0]++; tests.push((e) => e.id === n); any = true; continue; }
        if (c === '.') {
          i++; const n = ident(); if (!n) fail(); spec[1]++;
          tests.push((e) => { const v = __ptGetA(e, 'class'); return v != null && (' ' + v.replace(/[\t\n\f\r ]+/g, ' ') + ' ').indexOf(' ' + n + ' ') >= 0; });
          any = true; continue;
        }
        if (c === '[') {
          i++; ws();
          let name = ident();
          if (s[i] === '|' && s[i + 1] !== '=') { i++; name = ident(); }
          ws();
          let op = null, val = '', flag = '';
          if (s[i] === ']') i++;
          else {
            const m = /^([~^$*|]?=)/.exec(s.slice(i));
            if (!m) fail();
            op = m[1]; i += op.length; ws();
            if (s[i] === '"' || s[i] === "'") {
              const q = s[i++]; let v = '';
              while (i < s.length && s[i] !== q) { if (s[i] === '\\') { v += s[i + 1] || ''; i += 2; } else v += s[i++]; }
              i++; val = v;
            } else val = ident();
            ws();
            if (/[isIS]/.test(s[i] || '') && !/[\w-]/.test(s[i + 1] || '')) { flag = s[i].toLowerCase(); i++; ws(); }
            if (s[i] !== ']') fail();
            i++;
          }
          spec[1]++; any = true;
          const nm = name.toLowerCase();
          const ci = flag === 'i';
          const want = ci ? val.toLowerCase() : val;
          tests.push((e) => {
            let a = __ptGetA(e, nm);
            if (a == null && nm !== name) a = __ptGetA(e, name);
            if (a == null) return false;
            if (!op) return true;
            if (ci) a = a.toLowerCase();
            switch (op) {
              case '=': return a === want;
              case '^=': return want !== '' && a.startsWith(want);
              case '$=': return want !== '' && a.endsWith(want);
              case '*=': return want !== '' && a.indexOf(want) >= 0;
              case '~=': return want !== '' && !/\s/.test(want) && a.split(/[\t\n\f\r ]+/).indexOf(want) >= 0;
              case '|=': return a === want || a.startsWith(want + '-');
            }
            return false;
          });
          continue;
        }
        if (c === ':' && s[i + 1] === ':') {
          // Псевдоэлемент: элемент им не бывает.
          i += 2; ident(); if (s[i] === '(') paren();
          spec[2]++; any = true; tests.push(__SEL_NEVER);
          continue;
        }
        if (c === ':') {
          i++;
          const name = ident().toLowerCase();
          if (!name) fail();
          // Старые псевдоэлементы с одним двоеточием.
          if (/^(before|after|first-line|first-letter)$/.test(name)) { spec[2]++; any = true; tests.push(__SEL_NEVER); continue; }
          const arg = s[i] === '(' ? paren() : null;
          const r = __selPseudo(name, arg);
          spec[0] += r.spec[0]; spec[1] += r.spec[1]; spec[2] += r.spec[2];
          tests.push(r.test); any = true;
          continue;
        }
        if (c === '&') { i++; any = true; spec[1]++; tests.push((e, ctx) => !!(ctx && ctx.scope) && e === ctx.scope); continue; }
        break;
      }
      if (!any) fail();
      const n = tests.length;
      const test = n === 0 ? () => true : n === 1 ? tests[0]
        : (e, ctx) => { for (let k = 0; k < n; k++) if (!tests[k](e, ctx)) return false; return true; };
      return { test, spec };
    };
    // Сложный селектор; `relative` — для `:has()`, где он может начинаться с
    // комбинатора.
    const complex = (relative) => {
      const comps = [], combs = [];
      const spec = [0, 0, 0];
      ws();
      let lead = null;
      if (relative && /[>+~]/.test(s[i] || '')) { lead = s[i++]; ws(); }
      for (;;) {
        const c = compound();
        comps.push(c.test);
        spec[0] += c.spec[0]; spec[1] += c.spec[1]; spec[2] += c.spec[2];
        const had = ws();
        if (i >= s.length) break;
        const ch = s[i];
        if (ch === '>' || ch === '+' || ch === '~') { i++; ws(); combs.push(ch); continue; }
        if (ch === ',' || ch === ')') break;
        if (had) { combs.push(' '); continue; }
        fail();
      }
      return { comps, combs, spec, lead };
    };
    const list = (relative) => {
      const out = [];
      for (;;) {
        out.push(complex(relative));
        ws();
        if (s[i] === ',') { i++; continue; }
        break;
      }
      if (i < s.length) fail();
      return out;
    };
    return list(false);
  }

  const __parentEl = (e) => { const p = e.parentNode; return p && p.nodeType === ELEMENT_NODE ? p : null; };
  const __prevEl = (e) => { let p = e.previousSibling; while (p && p.nodeType !== ELEMENT_NODE) p = p.previousSibling; return p; };
  const __nextEl = (e) => { let p = e.nextSibling; while (p && p.nodeType !== ELEMENT_NODE) p = p.nextSibling; return p; };

  function __selMatchComplex(el, cx, idx, ctx) {
    if (!cx.comps[idx](el, ctx)) return false;
    if (idx === 0) {
      if (!cx.lead && !cx.anchored) return true;
      // `:has(> a)`: слева — сам якорь.
      const a = ctx.hasAnchor;
      const comb = cx.lead || ' ';
      if (comb === '>') return __parentEl(el) === a;
      if (comb === ' ') { for (let p = __parentEl(el); p; p = __parentEl(p)) if (p === a) return true; return false; }
      if (comb === '+') return __prevEl(el) === a;
      for (let p = __prevEl(el); p; p = __prevEl(p)) if (p === a) return true;
      return false;
    }
    const comb = cx.combs[idx - 1];
    if (comb === '>') { const p = __parentEl(el); return !!p && __selMatchComplex(p, cx, idx - 1, ctx); }
    if (comb === ' ') {
      for (let p = __parentEl(el); p; p = __parentEl(p)) if (__selMatchComplex(p, cx, idx - 1, ctx)) return true;
      return false;
    }
    if (comb === '+') { const p = __prevEl(el); return !!p && __selMatchComplex(p, cx, idx - 1, ctx); }
    for (let p = __prevEl(el); p; p = __prevEl(p)) if (__selMatchComplex(p, cx, idx - 1, ctx)) return true;
    return false;
  }

  function __selCompiled(sel) {
    const key = String(sel);
    let hit = __selCache.get(key);
    if (hit !== undefined) return hit;
    try { hit = __selParse(key); } catch (e) { hit = null; }
    if (__selCache.size > 5000) __selCache.clear();
    __selCache.set(key, hit);
    return hit;
  }
  const __selAny = (list, e, ctx) => {
    for (const cx of list) if (__selMatchComplex(e, cx, cx.comps.length - 1, ctx)) return true;
    return false;
  };
  const __maxSpec = (list) => list.reduce((m, cx) => {
    const a = cx.spec, b = m;
    return (a[0] - b[0] || a[1] - b[1] || a[2] - b[2]) > 0 ? a : b;
  }, [0, 0, 0]);
  // Список внутри `:is()`/`:where()` прощающий: непонятная часть просто
  // выпадает, а не губит всё.
  const __selForgiving = (arg) => {
    const out = [];
    for (const part of __selSplit(arg)) {
      if (!part) continue;
      const c = __selCompiled(part);
      if (c) out.push(...c);
    }
    return out;
  };
  // An+B из `:nth-child()`.
  function __nthParse(t) {
    t = t.trim().toLowerCase().replace(/\s+/g, '');
    if (t === 'odd') return [2, 1];
    if (t === 'even') return [2, 0];
    let m = /^([+-]?\d*)n([+-]\d+)?$/.exec(t);
    if (m) {
      const a = m[1] === '' || m[1] === '+' ? 1 : m[1] === '-' ? -1 : parseInt(m[1], 10);
      return [a, m[2] ? parseInt(m[2], 10) : 0];
    }
    if ((m = /^[+-]?\d+$/.exec(t))) return [0, parseInt(t, 10)];
    return null;
  }
  const __nthOk = (ab, pos) => {
    const [a, b] = ab;
    if (a === 0) return pos === b;
    const n = (pos - b) / a;
    return Number.isInteger(n) && n >= 0;
  };
  const __FORM_CTL = new Set(['button', 'input', 'select', 'textarea', 'optgroup', 'option', 'fieldset']);
  const __TEXTISH = /^(text|search|url|tel|email|password|date|month|week|time|datetime-local|number)$/;
  const __inputType = (e) => String(__ptGetA(e, 'type') || 'text').toLowerCase();
  const __isDisabled = (e) => {
    if (!__FORM_CTL.has(e.localName)) return false;
    if (__ptHasA(e, 'disabled')) return true;
    for (let p = __parentEl(e); p; p = __parentEl(p)) {
      if (p.localName === 'fieldset' && __ptHasA(p, 'disabled')) {
        // Кроме того, что лежит в первой легенде.
        const legend = [...p.children].find((k) => k.localName === 'legend');
        if (!(legend && legend.contains(e))) return true;
      }
    }
    return false;
  };
  const __valueOf = (e) => { try { return String(e.value == null ? '' : e.value); } catch (x) { return ''; } };
  const __isInvalid = (e) => {
    const t = e.localName;
    if (t === 'form' || t === 'fieldset') {
      let bad = false;
      walk(e, (k) => { if (!bad && __isInvalid(k)) bad = true; });
      return bad;
    }
    if (!(t === 'input' || t === 'select' || t === 'textarea') || __isDisabled(e)) return false;
    if (t === 'input' && /^(hidden|submit|reset|button|image)$/.test(__inputType(e))) return false;
    if (__ptHasA(e, 'required')) {
      if (t === 'input' && /^(checkbox|radio)$/.test(__inputType(e))) return !e.checked;
      if (__valueOf(e) === '') return true;
    }
    return false;
  };

  function __selPseudo(name, arg) {
    const B = [0, 1, 0];
    const doc = () => globalThis.document;
    const sib = (e, dir, same) => {
      let n = 1;
      for (let p = dir < 0 ? __prevEl(e) : __nextEl(e); p; p = dir < 0 ? __prevEl(p) : __nextEl(p)) {
        if (!same || p.localName === e.localName) n++;
      }
      return n;
    };
    switch (name) {
      case 'root': return { spec: B, test: (e) => !!e.ownerDocument && e === e.ownerDocument.documentElement };
      case 'scope': return { spec: B, test: (e, ctx) => (ctx && ctx.scope && ctx.scope.nodeType === ELEMENT_NODE ? e === ctx.scope : !!e.ownerDocument && e === e.ownerDocument.documentElement) };
      case 'is': case 'matches': case '-webkit-any': case 'where': {
        const list = __selForgiving(arg || '');
        return { spec: name === 'where' ? [0, 0, 0] : __maxSpec(list),
          test: (e, ctx) => __selAny(list, e, ctx) };
      }
      case 'not': {
        const list = __selCompiled(arg || '');
        if (!list) throw new SyntaxError('selector');
        return { spec: __maxSpec(list), test: (e, ctx) => !__selAny(list, e, ctx) };
      }
      case 'has': {
        const parts = __selSplit(arg || '');
        const rel = [];
        for (const p of parts) {
          let one;
          try { one = __selParseRelative(p); } catch (x) { one = null; }
          if (one) rel.push(one);
        }
        if (!rel.length) throw new SyntaxError('selector');
        return {
          spec: __maxSpec(rel),
          test: (e) => {
            for (const cx of rel) {
              const ctx = { hasAnchor: e };
              const lead = cx.lead || ' ';
              const scope = lead === '+' || lead === '~' ? __parentEl(e) : e;
              if (!scope) continue;
              let found = false;
              walk(scope, (k) => { if (!found && __selMatchComplex(k, cx, cx.comps.length - 1, ctx)) found = true; });
              if (found) return true;
            }
            return false;
          },
        };
      }
      case 'first-child': return { spec: B, test: (e) => !__prevEl(e) && !!e.parentNode };
      case 'last-child': return { spec: B, test: (e) => !__nextEl(e) && !!e.parentNode };
      case 'only-child': return { spec: B, test: (e) => !__prevEl(e) && !__nextEl(e) && !!e.parentNode };
      case 'first-of-type': return { spec: B, test: (e) => sib(e, -1, true) === 1 };
      case 'last-of-type': return { spec: B, test: (e) => sib(e, 1, true) === 1 };
      case 'only-of-type': return { spec: B, test: (e) => sib(e, -1, true) === 1 && sib(e, 1, true) === 1 };
      case 'nth-child': case 'nth-last-child': case 'nth-of-type': case 'nth-last-of-type': {
        let expr = String(arg || ''), of = null;
        const m = /^(.*?)\s+of\s+(.*)$/i.exec(expr);
        if (m && /child/.test(name)) { expr = m[1]; of = __selCompiled(m[2]); if (!of) throw new SyntaxError('selector'); }
        const ab = __nthParse(expr);
        if (!ab) throw new SyntaxError('selector');
        const last = /last/.test(name), type = /type/.test(name);
        const spec = of ? [B[0] + __maxSpec(of)[0], B[1] + __maxSpec(of)[1], __maxSpec(of)[2]] : B;
        return {
          spec,
          test: (e, ctx) => {
            if (!e.parentNode) return false;
            if (of && !__selAny(of, e, ctx)) return false;
            let n = 1;
            for (let p = last ? __nextEl(e) : __prevEl(e); p; p = last ? __nextEl(p) : __prevEl(p)) {
              if (type ? p.localName === e.localName : !of || __selAny(of, p, ctx)) n++;
            }
            return __nthOk(ab, n);
          },
        };
      }
      case 'empty': return { spec: B, test: (e) => !(e.__ptKids || []).some((k) => k.nodeType === ELEMENT_NODE || ((k.nodeType === TEXT_NODE || k.nodeType === 4) && k.data !== '')) };
      case 'checked': return { spec: B, test: (e) => (e.localName === 'input' && /^(checkbox|radio)$/.test(__inputType(e)) && !!e.checked) || (e.localName === 'option' && !!e.selected) };
      case 'indeterminate': return { spec: B, test: (e) => e.localName === 'input' && __inputType(e) === 'checkbox' && !!e.indeterminate };
      case 'default': return { spec: B, test: (e) => (e.localName === 'input' && /^(checkbox|radio)$/.test(__inputType(e)) && __ptHasA(e, 'checked')) || (e.localName === 'option' && __ptHasA(e, 'selected')) };
      case 'disabled': return { spec: B, test: (e) => __isDisabled(e) };
      case 'enabled': return { spec: B, test: (e) => __FORM_CTL.has(e.localName) && !__isDisabled(e) };
      case 'required': return { spec: B, test: (e) => /^(input|select|textarea)$/.test(e.localName) && __ptHasA(e, 'required') };
      case 'optional': return { spec: B, test: (e) => /^(input|select|textarea)$/.test(e.localName) && !__ptHasA(e, 'required') };
      case 'read-write': case 'read-only': {
        const rw = (e) => {
          if (e.localName === 'textarea') return !__ptHasA(e, 'readonly') && !__isDisabled(e);
          if (e.localName === 'input') return __TEXTISH.test(__inputType(e)) && !__ptHasA(e, 'readonly') && !__isDisabled(e);
          for (let p = e; p; p = __parentEl(p)) {
            const v = __ptGetA(p, 'contenteditable');
            if (v != null) return v !== 'false';
          }
          return false;
        };
        return { spec: B, test: name === 'read-write' ? rw : (e) => !rw(e) };
      }
      case 'placeholder-shown': return { spec: B, test: (e) => (e.localName === 'input' || e.localName === 'textarea') && __ptHasA(e, 'placeholder') && __valueOf(e) === '' };
      case 'valid': return { spec: B, test: (e) => /^(input|select|textarea|form|fieldset)$/.test(e.localName) && !__isInvalid(e) };
      case 'invalid': return { spec: B, test: (e) => __isInvalid(e) };
      case 'link': case 'any-link': case '-webkit-any-link': return { spec: B, test: (e) => (e.localName === 'a' || e.localName === 'area') && __ptHasA(e, 'href') };
      case 'focus': return { spec: B, test: (e) => { const d = e.ownerDocument; return !!d && d.__ptActive === e; } };
      case 'focus-within': return { spec: B, test: (e) => { const d = e.ownerDocument; const a = d && d.__ptActive; return !!a && (a === e || e.contains(a)); } };
      case 'target': return { spec: B, test: (e) => { try { const h = decodeURIComponent(String(globalThis.location && globalThis.location.hash || '').slice(1)); return !!h && e.id === h; } catch (x) { return false; } } };
      case 'lang': {
        const want = String(arg || '').trim().replace(/^["']|["']$/g, '').toLowerCase();
        return { spec: B, test: (e) => {
          for (let p = e; p; p = __parentEl(p)) {
            const v = __ptGetA(p, 'lang');
            if (v != null) { const l = v.toLowerCase(); return l === want || l.startsWith(want + '-'); }
          }
          return false;
        } };
      }
      case 'dir': {
        const want = String(arg || '').trim().toLowerCase();
        return { spec: B, test: (e) => {
          for (let p = e; p; p = __parentEl(p)) {
            const v = String(__ptGetA(p, 'dir') || '').toLowerCase();
            if (v === 'ltr' || v === 'rtl') return v === want;
          }
          return want === 'ltr';
        } };
      }
      case 'open': return { spec: B, test: (e) => (e.localName === 'details' || e.localName === 'dialog') && __ptHasA(e, 'open') };
      case 'defined': return { spec: B, test: (e) => e.localName.indexOf('-') < 0 || !!(globalThis.customElements && globalThis.customElements.get && globalThis.customElements.get(e.localName)) };
      case 'host': case 'host-context': case 'state':
        return { spec: B, test: __SEL_NEVER };
    }
    // Всё прочее — состояния, которых у нас не бывает (`:hover`,
    // `:active`, `:visited`, `:autofill`, `:fullscreen`, `:modal`…), и
    // приставочные имена. Совпадения нет, но и ошибки тоже.
    return { spec: B, test: __SEL_NEVER };
  }
  function __selParseRelative(src) {
    // Относительный селектор: тот же разбор, но с комбинатором впереди и
    // привязкой к якорю слева.
    const t = String(src).trim();
    const lead = /^[>+~]/.test(t) ? t[0] : null;
    const body = lead ? t.slice(1) : t;
    const parsed = __selParse(body);
    if (parsed.length !== 1) throw new SyntaxError('selector');
    const cx = parsed[0];
    cx.lead = lead; cx.anchored = true;
    return cx;
  }

  // Селектор, который браузер разобрать не может, — это отказ, а не пустой
  // ответ: `document.querySelector('<<<')` бросает SyntaxError с точным текстом.
  // У нас же он что-то находил — движок молча пропускал непонятное, и `<<<`
  // отвечал первым элементом, а `matches('###')` отвечал «да».
  const __selectorOk = (sel) => {
    const s = String(sel);
    if (!s.trim()) return false;
    // Части через запятую проверяются по отдельности, как в браузере.
    for (const part of __selSplit(s)) {
      const t = part.trim();
      if (!t) return false;
      if (/[<>~+]$/.test(t) || /^[>~+]/.test(t)) return false;
      // Скобки должны сходиться.
      let depth = 0, square = 0;
      for (const ch of t) {
        if (ch === '(') depth++;
        else if (ch === ')') { if (--depth < 0) return false; }
        else if (ch === '[') square++;
        else if (ch === ']') { if (--square < 0) return false; }
        else if (ch === '<') return false;              // в селекторе не бывает
      }
      if (depth || square) return false;
      // `#`, `.` и `:` обязаны вести к имени.
      if (/[#.](?![-\w\\])/.test(t)) return false;
      if (/:(?![-\w:(])/.test(t)) return false;
    }
    return true;
  };
  const __checkSelector = (sel, method, iface) => {
    if (__selectorOk(sel)) return String(sel);
    const msg = "Failed to execute '" + method + "' on '" + iface + "': '" +
      String(sel) + "' is not a valid selector.";
    throw new (globalThis.DOMException || Error)(msg, 'SyntaxError');
  };
  // Столько же доводов, сколько требует браузер, и тот же текст отказа.
  const __needArgs = (got, want, method, iface) => {
    if (got >= want) return;
    throw new TypeError("Failed to execute '" + method + "' on '" + iface + "': " +
      want + " argument" + (want === 1 ? '' : 's') + " required, but only " + got + " present.");
  };

  // Не узел там, где нужен узел. Браузер отвечает своим `TypeError` ещё до
  // всякой работы, и текст у него слово в слово такой; у нас вместо него
  // вылезало внутреннее «Cannot read properties of undefined», то есть
  // подпись движка. Чужой код это читает: челлендж Cloudflare нарочно зовёт
  // `replaceChild` не тем и сверяет, что ему ответили.
  const __needNode = (v, n, method, iface) => {
    if (v !== null && typeof v === 'object' && typeof v.nodeType === 'number') return;
    throw new TypeError("Failed to execute '" + method + "' on '" + (iface || 'Node') + "': " +
      "parameter " + n + " is not of type 'Node'.");
  };

  // Узел, перед которым (или вместо которого) просят вставить, обязан быть
  // ребёнком. Браузер на чужом узле бросает `NotFoundError` своими словами.
  const __needChild = (parent, ref, method, what) => {
    if (parent.__ptKids.indexOf(ref) >= 0) return;
    throw new (globalThis.DOMException || Error)(
      "Failed to execute '" + method + "' on 'Node': " + what, 'NotFoundError');
  };

  function matchesSelector(el, selector, scope) {
    if (!el || el.nodeType !== ELEMENT_NODE) return false;
    const list = __selCompiled(selector);
    return !!list && __selAny(list, el, { scope: scope || null });
  }
  // Ответ — в порядке документа: `querySelectorAll('input, button')` у
  // браузера отдаёт элементы так, как они стоят в дереве (api.js Turnstile
  // описывает форму именно этим запросом).
  function query(root, selector) {
    const results = [];
    const list = __selCompiled(selector);
    if (list) {
      const ctx = { scope: root };
      walk(root, (e) => { if (__selAny(list, e, ctx)) results.push(e); });
    }
    results.item = (i) => results[i] || null;
    return results;
  }

  // ---- HTML serialization (innerHTML getter) --------------------------------
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
  const esc = (s, attr) => s.replace(attr ? /[&<>"]/g : /[&<>]/g, c => ESC[c]);
  function serializeNode(n, withShadow) {
    if (n.nodeType === TEXT_NODE) return esc(n.data, false);
    if (n.nodeType === COMMENT_NODE) return `<!--${n.data}-->`;
    if (n.nodeType !== ELEMENT_NODE) return n.__ptKids.map((c) => serializeNode(c, withShadow)).join('');
    const tag = n.localName;
    let attrs = '';
    for (const { name, value } of n.attributes) attrs += ` ${name}="${esc(value, true)}"`;
    if (VOID.has(tag)) return `<${tag}${attrs}>`;
    // `<template>` сериализует своё содержимое; сериализуемый теневой корень
    // (getHTML с serializableShadowRoots) — как <template shadowrootmode>.
    let inner = '';
    if (withShadow && n.__ptShadow && n.__ptShadow.__ptSerializable) {
      const sr = n.__ptShadow;
      inner += `<template shadowrootmode="${sr.mode}"${sr.__ptDelegatesFocus ? ' shadowrootdelegatesfocus=""' : ''}${sr.__ptSerializable ? ' shadowrootserializable=""' : ''}${sr.__ptClonable ? ' shadowrootclonable=""' : ''}>${sr.__ptKids.map((c) => serializeNode(c, withShadow)).join('')}</template>`;
    }
    const kids = tag === 'template' ? __templateContent(n).__ptKids : n.__ptKids;
    inner += kids.map((c) => serializeNode(c, withShadow)).join('');
    return `<${tag}${attrs}>${inner}</${tag}>`;
  }

  // ---- HTML fragment parser (innerHTML setter) ------------------------------
  // A forgiving tokenizer: handles tags, attributes (quoted/unquoted/bare),
  // text, comments, and void/self-closing elements. Not spec-perfect, but
  // covers the markup scripts typically inject.
  const __SVG_NS = 'http://www.w3.org/2000/svg', __MATH_NS = 'http://www.w3.org/1998/Math/MathML';
  // Таблицы регистра из спецификации HTML (adjust SVG tag/attribute names).
  const __SVG_CASE = {};
  for (const n of ['altGlyph', 'altGlyphDef', 'altGlyphItem', 'animateColor', 'animateMotion', 'animateTransform', 'clipPath', 'feBlend', 'feColorMatrix', 'feComponentTransfer', 'feComposite', 'feConvolveMatrix', 'feDiffuseLighting', 'feDisplacementMap', 'feDistantLight', 'feDropShadow', 'feFlood', 'feFuncA', 'feFuncB', 'feFuncG', 'feFuncR', 'feGaussianBlur', 'feImage', 'feMerge', 'feMergeNode', 'feMorphology', 'feOffset', 'fePointLight', 'feSpecularLighting', 'feSpotLight', 'feTile', 'feTurbulence', 'foreignObject', 'glyphRef', 'linearGradient', 'radialGradient', 'textPath']) __SVG_CASE[n.toLowerCase()] = n;
  const __SVG_ATTR_CASE = {};
  for (const n of ['attributeName', 'attributeType', 'baseFrequency', 'baseProfile', 'calcMode', 'clipPathUnits', 'diffuseConstant', 'edgeMode', 'filterUnits', 'glyphRef', 'gradientTransform', 'gradientUnits', 'kernelMatrix', 'kernelUnitLength', 'keyPoints', 'keySplines', 'keyTimes', 'lengthAdjust', 'limitingConeAngle', 'markerHeight', 'markerUnits', 'markerWidth', 'maskContentUnits', 'maskUnits', 'numOctaves', 'pathLength', 'patternContentUnits', 'patternTransform', 'patternUnits', 'pointsAtX', 'pointsAtY', 'pointsAtZ', 'preserveAlpha', 'preserveAspectRatio', 'primitiveUnits', 'refX', 'refY', 'repeatCount', 'repeatDur', 'requiredExtensions', 'requiredFeatures', 'specularConstant', 'specularExponent', 'spreadMethod', 'startOffset', 'stdDeviation', 'stitchTiles', 'surfaceScale', 'systemLanguage', 'tableValues', 'targetX', 'targetY', 'textLength', 'viewBox', 'viewTarget', 'xChannelSelector', 'yChannelSelector', 'zoomAndPan']) __SVG_ATTR_CASE[n.toLowerCase()] = n;
  const __foreignElem = (doc, ns, name) => {
    const O = globalThis.__pt_orig || {};
    const f = O.createElementNS || Document.prototype.createElementNS;
    return f.call(doc, ns, name);
  };
  function parseFragment(html) {
    const doc = globalThis.document;
    // Разбор идёт мимо имён, которые видит страница: в браузере присваивание
    // `innerHTML` не зовёт ни `createElement`, ни `appendChild`, ни
    // `setAttribute`, а у нас каждая вставка разметки показывала их десятками
    // всякому, кто эти методы обернул.
    const O = globalThis.__pt_orig || {};
    const mk = (name, self, args) => (O[name] ? O[name].apply(self, args) : self[name].apply(self, args));
    const frag = () => mk('createDocumentFragment', doc, []);
    const text = (t) => mk('createTextNode', doc, [t]);
    const note = (t) => mk('createComment', doc, [t]);
    const elem = (t) => mk('createElement', doc, [t]);
    const put = (parent, child) => __ptAdd.call(parent, child);
    const attr = (el, n, v) => __ptSetAttr.call(el, n, v);
    const root = frag();
    const stack = [root];
    const top = () => stack[stack.length - 1];
    let i = 0;
    while (i < html.length) {
      if (html[i] === '<') {
        if (html.startsWith('<!--', i)) {
          const end = html.indexOf('-->', i + 4);
          const stop = end < 0 ? html.length : end;
          put(top(), note(html.slice(i + 4, stop)));
          i = end < 0 ? html.length : end + 3; continue;
        }
        const close = html[i + 1] === '/';
        const m = /^<\/?([a-zA-Z][\w-]*)((?:[^>"']|"[^"]*"|'[^']*')*)\/?>/.exec(html.slice(i));
        if (!m) { put(top(), text('<')); i++; continue; }
        const tag = m[1].toLowerCase();
        if (close) {
          for (let s = stack.length - 1; s > 0; s--) if (String(stack[s].localName).toLowerCase() === tag) { stack.length = s; break; }
        } else if (tag === 'html' || tag === 'head' || tag === 'body') {
          // Разбор куска разметки: браузер такие теги внутрь не вставляет —
          // их содержимое просто переезжает в текущего родителя. Мы делали
          // из них узлы, и `div.innerHTML = '<html><body></body></html>'`
          // давал двух детей там, где у браузера пусто.
        } else {
          // Подразумеваемое закрытие, как у разбора HTML: новый блочный тег
          // закрывает открытый <p>, `<li>` — открытый <li>, и т. п. Без этого
          // `<p>a<p>b` вкладывался, а Chrome даёт двух соседей.
          const CLOSES_P = new Set(['address', 'article', 'aside', 'blockquote', 'details', 'dialog', 'div', 'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'main', 'menu', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'ul']);
          const SELF_CLOSES = { li: ['li'], dt: ['dt', 'dd'], dd: ['dt', 'dd'], option: ['option', 'optgroup'], optgroup: ['optgroup'], tr: ['tr', 'td', 'th'], td: ['td', 'th'], th: ['td', 'th'], thead: ['tbody', 'tfoot', 'thead'], tbody: ['tbody', 'tfoot', 'thead'], tfoot: ['tbody', 'tfoot', 'thead'] };
          if (CLOSES_P.has(tag)) { for (let s = stack.length - 1; s > 0; s--) { if (stack[s].localName === 'p') { stack.length = s; break; } if (CLOSES_P.has(stack[s].localName) && stack[s].localName !== 'p') break; } }
          const closes = SELF_CLOSES[tag];
          if (closes) { for (let s = stack.length - 1; s > 0; s--) { const ln = stack[s].localName; if (closes.indexOf(ln) >= 0) { stack.length = s; break; } if (ln === 'table' || ln === 'ul' || ln === 'ol' || ln === 'select' || ln === 'dl') break; } }
          // Подразумеваемые обёртки таблицы: `<table><tr>` получает `<tbody>`,
          // а `<td>` без строки — `<tr>`; браузер вставляет их сам, и
          // `table.tBodies[0].rows` у него есть всегда.
          if (tag === 'tr' || tag === 'td' || tag === 'th') {
            const tl = top().localName;
            if (tag === 'tr' && tl === 'table') { const tb = elem('tbody'); put(top(), tb); stack.push(tb); }
            else if ((tag === 'td' || tag === 'th') && (tl === 'table' || tl === 'tbody' || tl === 'thead' || tl === 'tfoot')) {
              if (tl === 'table') { const tb = elem('tbody'); put(top(), tb); stack.push(tb); }
              const row = elem('tr'); put(top(), row); stack.push(row);
            }
          }
          // Чужое содержимое, как у разбора HTML: внутри <svg> — элементы SVG
          // (с регистром имён по таблице спецификации), внутри <math> — MathML,
          // внутри foreignObject/desc/title у SVG — снова HTML. Раньше <svg> из
          // innerHTML становился HTMLUnknownElement, а значки виджета — с ним.
          const parentNS = (() => {
            const t = top(); const pns = t && t.__ptNS;
            if (pns === __SVG_NS && (t.__ptLocal === 'foreignObject' || t.__ptLocal === 'desc' || t.__ptLocal === 'title')) return null;
            if (pns === __MATH_NS && t.__ptLocal === 'annotation-xml') return null;
            return pns === __SVG_NS || pns === __MATH_NS ? pns : null;
          })();
          const ns = parentNS || (tag === 'svg' ? __SVG_NS : tag === 'math' ? __MATH_NS : null);
          const el = ns ? __foreignElem(doc, ns, ns === __SVG_NS ? (__SVG_CASE[tag] || tag) : tag) : elem(tag);
          for (const am of m[2].matchAll(/([\w:-]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g)) {
            let v = am[2] || '';
            if (v && (v[0] === '"' || v[0] === "'")) v = v.slice(1, -1);
            // Ссылки на знаки в значении разбираются, как и в тексте: `&quot;`
            // становится кавычкой, а при сериализации — снова `&quot;`, не `&amp;quot;`.
            const an = am[1].toLowerCase();
            attr(el, ns === __SVG_NS ? (__SVG_ATTR_CASE[an] || an) : an, unescapeEntities(v));
          }
          put(top(), el);
          const selfClose = m[0].endsWith('/>') && (ns || VOID.has(tag)) || VOID.has(tag) && !ns;
          if (!selfClose) stack.push(el);
        }
        i += m[0].length;
      } else {
        const next = html.indexOf('<', i);
        const stop = next < 0 ? html.length : next;
        const chunk = html.slice(i, stop);
        if (chunk) put(top(), text(unescapeEntities(chunk)));
        i = stop;
      }
    }
    return root.__ptKids.slice();
  }
  const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '\u00a9', reg: '\u00ae', trade: '\u2122', hellip: '\u2026', mdash: '\u2014', ndash: '\u2013', laquo: '\u00ab', raquo: '\u00bb', times: '\u00d7', middot: '\u00b7', bull: '\u2022', lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201c', rdquo: '\u201d', euro: '\u20ac', pound: '\u00a3', yen: '\u00a5', cent: '\u00a2', sect: '\u00a7', deg: '\u00b0', plusmn: '\u00b1', para: '\u00b6', shy: '\u00ad', iexcl: '\u00a1', iquest: '\u00bf', larr: '\u2190', rarr: '\u2192', uarr: '\u2191', darr: '\u2193', ensp: '\u2002', emsp: '\u2003', thinsp: '\u2009', zwnj: '\u200c', zwj: '\u200d' };
  function unescapeEntities(s) {
    if (s.indexOf('&') < 0) return s;
    return s.replace(/&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g, (m, e) => {
      if (e[0] === '#') {
        const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\ufffd';
        return String.fromCodePoint(cp);
      }
      return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, e) ? NAMED_ENTITIES[e] : m;
    });
  }

  // ---- build DOM from the Rust-parsed tree ----------------------------------
  // `<template>` держит разобранное содержимое не в себе, а в отдельном
  // DocumentFragment: `t.content`. У нас его не было вовсе, разобранные дети
  // терялись, и код, который строит узлы через шаблон — а так делает и
  // челлендж Cloudflare — получал undefined там, где ждал фрагмент.
  function __templateContent(el) {
    let f = el.__ptContent;
    if (!f) {
      f = (el.ownerDocument || globalThis.document).createDocumentFragment();
      Object.defineProperty(el, '__ptContent', { value: f, writable: true, enumerable: false });
    }
    return f;
  }
  globalThis.__pt_templateContent = __templateContent;

  function buildNode(doc, spec) {
    if (spec.k === 't') return doc.createTextNode(spec.v);
    if (spec.k === 'c') return doc.createComment(spec.v);
    const el = spec.ns ? __foreignElem(doc, spec.ns, spec.tag) : doc.createElement(spec.tag);
    // A parser-built script is "already started": the engine runs the document's
    // scripts itself, in document order, so connecting the tree must not run them
    // a second time. Only what a page inserts later goes through `__ptRunScript`.
    if (spec.tag === 'script') {
      Object.defineProperty(el, '__ptRan', { value: true, configurable: true, enumerable: false });
    }
    for (const [name, value] of spec.attrs) __ptSetA(el, name, value);
    // Разбор кладёт детей шаблона в его содержимое, а сам элемент оставляет
    // пустым — `t.childNodes.length === 0` и в браузере тоже.
    const into = spec.tag === 'template' ? __templateContent(el) : el;
    for (const child of spec.children) into.appendChild(buildNode(doc, child));
    return el;
  }

  // ---- install globals ------------------------------------------------------
  const document = new Document();
  globalThis.document = document;
  // Standard Node type constants, on the constructor and the prototype — drivers
  // check `node.nodeType !== Node.ELEMENT_NODE` before acting on a node.
  const NODE_TYPES = {
    ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3, CDATA_SECTION_NODE: 4,
    // Пятый и шестой типы давно не создаются, но константы у Node остались, и
    // их пересчитывают: у Chrome на `Node.prototype` ровно 48 имён.
    ENTITY_REFERENCE_NODE: 5, ENTITY_NODE: 6,
    PROCESSING_INSTRUCTION_NODE: 7, COMMENT_NODE: 8, DOCUMENT_NODE: 9,
    DOCUMENT_TYPE_NODE: 10, DOCUMENT_FRAGMENT_NODE: 11, NOTATION_NODE: 12,
    DOCUMENT_POSITION_DISCONNECTED: 1, DOCUMENT_POSITION_PRECEDING: 2,
    DOCUMENT_POSITION_FOLLOWING: 4, DOCUMENT_POSITION_CONTAINS: 8,
    DOCUMENT_POSITION_CONTAINED_BY: 16, DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC: 32,
  };
  Object.assign(Node, NODE_TYPES);
  Object.assign(Node.prototype, NODE_TYPES);

  // Члены Node, которых у нас не было вовсе или которые лежали этажом ниже, на
  // Element. В браузере они все здесь, и сборщик отпечатка считает именно этот
  // этаж.
  const __nodeName = function () {
    switch (this.nodeType) {
      case 1: return this.tagName;
      case 3: return '#text';
      case 8: return '#comment';
      case 9: return '#document';
      case 10: return this.name || 'html';
      case 11: return '#document-fragment';
      default: return '#unknown';
    }
  };
  const __nodeMembers = {
    baseURI: { get: function () { const d = this.nodeType === 9 ? this : this.ownerDocument; return (d && d.URL) || (globalThis.location && location.href) || 'about:blank'; } },
    nodeName: { get: __nodeName },
    parentElement: { get: function () { const p = this.parentNode; return p && p.nodeType === 1 ? p : null; } },
    nodeValue: {
      get: function () { return (this.nodeType === 3 || this.nodeType === 8) ? this.data : null; },
      set: function (v) { if (this.nodeType === 3 || this.nodeType === 8) this.data = String(v); },
    },
    isSameNode: { value: function isSameNode(other) { return this === other; } },
    isEqualNode: {
      value: function isEqualNode(other) {
        if (!other || this.nodeType !== other.nodeType) return false;
        if (this.nodeName !== other.nodeName) return false;
        if (this.nodeType === 3 || this.nodeType === 8) return this.data === other.data;
        if (this.nodeType === 1) {
          const a = this.attributes || [], b = other.attributes || [];
          if (a.length !== b.length) return false;
          for (let i = 0; i < a.length; i++) {
            if (__ptGetA(other, a[i].name) !== a[i].value) return false;
          }
        }
        const x = this.childNodes, y = other.childNodes;
        if (x.length !== y.length) return false;
        for (let i = 0; i < x.length; i++) if (!x[i].isEqualNode(y[i])) return false;
        return true;
      },
    },
    compareDocumentPosition: {
      value: function compareDocumentPosition(other) {
        if (this === other) return 0;
        if (!other) return 1;
        if (this.contains && this.contains(other)) return 20;   // CONTAINED_BY | FOLLOWING
        if (other.contains && other.contains(this)) return 10;  // CONTAINS | PRECEDING
        const root = (n) => { while (n.parentNode) n = n.parentNode; return n; };
        if (root(this) !== root(other)) return 35;              // DISCONNECTED | IMPLEMENTATION_SPECIFIC | PRECEDING
        const order = [];
        (function walk(n) { order.push(n); for (const c of n.childNodes) walk(c); })(root(this));
        return order.indexOf(this) < order.indexOf(other) ? 4 : 2;
      },
    },
    normalize: {
      value: function normalize() {
        const kids = this.childNodes;
        for (let i = kids.length - 1; i > 0; i--) {
          const cur = kids[i], prev = kids[i - 1];
          if (cur.nodeType === 3 && prev.nodeType === 3) { prev.data += cur.data; this.removeChild(cur); }
        }
        for (const c of this.childNodes) if (c.normalize) c.normalize();
      },
    },
    isDefaultNamespace: { value: function isDefaultNamespace(ns) { return ns === 'http://www.w3.org/1999/xhtml'; } },
    lookupNamespaceURI: { value: function lookupNamespaceURI(prefix) { return prefix ? null : 'http://www.w3.org/1999/xhtml'; } },
    lookupPrefix: { value: function lookupPrefix() { return null; } },
  };
  for (const [name, spec] of Object.entries(__nodeMembers)) {
    if (Object.getOwnPropertyDescriptor(Node.prototype, name)) continue;
    try {
      Object.defineProperty(Node.prototype, name,
        Object.assign({ enumerable: true, configurable: true }, spec,
                      spec.value ? { writable: true } : {}));
    } catch (e) {}
  }
  // A WebIDL interface's members are *enumerable* on its prototype: in a browser
  // `Object.keys(Document.prototype)` lists `body`, `title`, `querySelector` and
  // the rest. Ours were declared with `class`, whose members are non-enumerable by
  // language rule, so the same call returned two names. That is not an internal
  // detail — the Turnstile VM fingerprints by walking `Object.keys` up the whole
  // prototype chain, and against a browser's 1600-odd properties our graph showed
  // 318. Mark them the way the platform does; `constructor` stays hidden, as it is
  // in a browser.
  const __webidl = (ctor) => {
    if (!ctor || !ctor.prototype) return;
    for (const k of Object.getOwnPropertyNames(ctor.prototype)) {
      if (k === 'constructor') continue;
      const d = Object.getOwnPropertyDescriptor(ctor.prototype, k);
      if (!d || d.enumerable || !d.configurable) continue;
      d.enumerable = true;
      try { Object.defineProperty(ctor.prototype, k, d); } catch (e) {}
    }
  };

  globalThis.Node = Node;
  globalThis.Element = Element;
  // В браузере интерфейсы элементов — лестница: Element → HTMLElement →
  // HTMLCanvasElement и так далее, и у каждой ступени свои члены. У нас все они
  // были **одним объектом**: `HTMLCanvasElement.prototype === HTMLDivElement
  // .prototype === Element.prototype`, поэтому `div instanceof HTMLCanvasElement`
  // отвечало true, а `constructor.name` любого элемента — `Element`. Строим
  // лестницу; сами члены пока живут на Element, их развес — следующим шагом.
  const __ifaceProto = new Map();
  let __pendingTag = 'div';
  // Строгий контекст здесь не украшение: у обычной функции есть собственные
  // `arguments` и `caller`, а у интерфейса браузера их нет — и обход графа
  // видел два лишних свойства у каждого из сотни имён `HTML*Element`.
  const __mkIface = (function () {
    'use strict';
    return (name, parentProto) => {
    const C = function () {
      // `new HTMLElement()` в браузере бросает, но `super()` из класса
      // кастомного элемента обязан работать — это его штатный путь.
      if (new.target && new.target !== C) return Reflect.construct(Element, [__pendingTag], new.target);
      throw new TypeError("Illegal constructor");
    };
    try { Object.defineProperty(C, 'name', { value: name, configurable: true }); } catch (e) {}
    C.prototype = Object.create(parentProto);
    Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true });
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
    globalThis[name] = globalThis.__pt_native ? __pt_native(C) : C;
    return C.prototype;
    };
  })();
  const __htmlProto = __mkIface('HTMLElement', Element.prototype);
  // Тег → интерфейс, снято с Chrome 148.
  const TAG_IFACE = {
    a: 'HTMLAnchorElement', area: 'HTMLAreaElement', audio: 'HTMLAudioElement',
    br: 'HTMLBRElement', base: 'HTMLBaseElement', body: 'HTMLBodyElement',
    button: 'HTMLButtonElement', canvas: 'HTMLCanvasElement', data: 'HTMLDataElement',
    datalist: 'HTMLDataListElement', del: 'HTMLModElement', details: 'HTMLDetailsElement',
    dialog: 'HTMLDialogElement', div: 'HTMLDivElement', dl: 'HTMLDListElement',
    embed: 'HTMLEmbedElement', fieldset: 'HTMLFieldSetElement', form: 'HTMLFormElement',
    h1: 'HTMLHeadingElement', h2: 'HTMLHeadingElement', h3: 'HTMLHeadingElement',
    h4: 'HTMLHeadingElement', h5: 'HTMLHeadingElement', h6: 'HTMLHeadingElement',
    head: 'HTMLHeadElement', hr: 'HTMLHRElement', html: 'HTMLHtmlElement',
    iframe: 'HTMLIFrameElement', img: 'HTMLImageElement', input: 'HTMLInputElement',
    ins: 'HTMLModElement', label: 'HTMLLabelElement', legend: 'HTMLLegendElement',
    li: 'HTMLLIElement', link: 'HTMLLinkElement', map: 'HTMLMapElement',
    menu: 'HTMLMenuElement', meta: 'HTMLMetaElement', meter: 'HTMLMeterElement',
    object: 'HTMLObjectElement', ol: 'HTMLOListElement', optgroup: 'HTMLOptGroupElement',
    option: 'HTMLOptionElement', output: 'HTMLOutputElement', p: 'HTMLParagraphElement',
    picture: 'HTMLPictureElement', pre: 'HTMLPreElement', progress: 'HTMLProgressElement',
    q: 'HTMLQuoteElement', blockquote: 'HTMLQuoteElement', script: 'HTMLScriptElement',
    select: 'HTMLSelectElement', slot: 'HTMLSlotElement', source: 'HTMLSourceElement',
    span: 'HTMLSpanElement', style: 'HTMLStyleElement', table: 'HTMLTableElement',
    caption: 'HTMLTableCaptionElement', td: 'HTMLTableCellElement', th: 'HTMLTableCellElement',
    col: 'HTMLTableColElement', colgroup: 'HTMLTableColElement', tr: 'HTMLTableRowElement',
    tbody: 'HTMLTableSectionElement', tfoot: 'HTMLTableSectionElement',
    thead: 'HTMLTableSectionElement', template: 'HTMLTemplateElement',
    textarea: 'HTMLTextAreaElement', time: 'HTMLTimeElement', title: 'HTMLTitleElement',
    track: 'HTMLTrackElement', ul: 'HTMLUListElement', video: 'HTMLVideoElement',
  };
  // Теги без своего интерфейса, но известные HTML: у них HTMLElement.
  const PLAIN_TAGS = new Set(['abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo',
    'cite', 'code', 'dd', 'dfn', 'dt', 'em', 'figcaption', 'figure', 'footer', 'header',
    'hgroup', 'i', 'kbd', 'main', 'mark', 'nav', 'noscript', 'rp', 'rt', 'ruby', 's',
    'samp', 'search', 'section', 'small', 'strong', 'sub', 'summary', 'sup', 'u', 'var',
    'wbr', 'center', 'font', 'big', 'strike', 'tt', 'nobr']);
  for (const name of new Set(Object.values(TAG_IFACE))) __ifaceProto.set(name, __mkIface(name, __htmlProto));
  // Мультимедиа наследует HTMLMediaElement, как в браузере.
  const __mediaProto = __mkIface('HTMLMediaElement', __htmlProto);
  for (const n of ['HTMLVideoElement', 'HTMLAudioElement']) {
    try { Object.setPrototypeOf(globalThis[n].prototype, __mediaProto); } catch (e) {}
  }
  __ifaceProto.set('HTMLUnknownElement', __mkIface('HTMLUnknownElement', __htmlProto));
  for (const n of ['HTMLFrameSetElement', 'HTMLFrameElement', 'HTMLMarqueeElement',
                   'HTMLDirectoryElement', 'HTMLFontElement', 'HTMLParamElement']) {
    if (!globalThis[n]) __mkIface(n, __htmlProto);
  }
  // Коллекции форм и таблиц: `table.rows`, `tr.cells`, `select.options`,
  // `form.elements`… Их не было вовсе, и `table.rows[0]` ронял страницу
  // (челлендж Cloudflare разбирает так свою тестовую разметку).
  {
    const proto = (n) => __ifaceProto.get(n);
    const defGet = (P, k, get) => { if (!P) return; try { Object.defineProperty(P, k, { get, enumerable: true, configurable: true }); } catch (e) {} };
    const defFn = (P, k, fn) => { if (!P) return; try { Object.defineProperty(P, k, { value: fn, writable: true, enumerable: true, configurable: true }); } catch (e) {} };
    const kids = (el) => (el && el.__ptKids ? el.__ptKids : []).filter((k) => k.nodeType === ELEMENT_NODE);
    const local = (el) => String(el.__ptLocal || '').toLowerCase();
    const isTag = (el, ...names) => el && el.nodeType === ELEMENT_NODE && names.includes(local(el));
    const branded = (arr, name) => {
      const c = __collection(arr);
      try { const I = globalThis[name]; if (I && I.prototype) Object.setPrototypeOf(c, I.prototype); } catch (e) {}
      return c;
    };
    // Таблица.
    const tableRows = (t) => {
      const out = [];
      const heads = kids(t).filter((k) => isTag(k, 'thead'));
      const feet = kids(t).filter((k) => isTag(k, 'tfoot'));
      for (const h of heads) for (const r of kids(h)) if (isTag(r, 'tr')) out.push(r);
      for (const k of kids(t)) {
        if (isTag(k, 'tr')) out.push(k);
        else if (isTag(k, 'tbody')) for (const r of kids(k)) if (isTag(r, 'tr')) out.push(r);
      }
      for (const f of feet) for (const r of kids(f)) if (isTag(r, 'tr')) out.push(r);
      return out;
    };
    const T = proto('HTMLTableElement');
    defGet(T, 'rows', function () { return __collection(tableRows(this)); });
    defGet(T, 'tBodies', function () { return __collection(kids(this).filter((k) => isTag(k, 'tbody'))); });
    const defAcc = (P, k, get, set) => { try { Object.defineProperty(P, k, { get, set, enumerable: true, configurable: true }); } catch (e) {} };
    const tableSet = (t, tag, v, where) => {
      if (v !== null && !(v && isTag(v, tag))) throw new TypeError("Failed to set the '" + (tag === 'thead' ? 'tHead' : tag === 'tfoot' ? 'tFoot' : tag) + "' property on 'HTMLTableElement': The provided value is not of type '" + (tag === 'caption' ? 'HTMLTableCaptionElement' : 'HTMLTableSectionElement') + "'.");
      const old = kids(t).find((k) => isTag(k, tag)); if (old) t.removeChild(old);
      if (!v) return;
      const ref = where(t); ref ? t.insertBefore(v, ref) : t.appendChild(v);
    };
    defAcc(T, 'tHead', function () { return kids(this).find((k) => isTag(k, 'thead')) || null; },
      function (v) { tableSet(this, 'thead', v, (t) => kids(t).find((k) => !isTag(k, 'caption') && !isTag(k, 'colgroup')) || null); });
    defAcc(T, 'tFoot', function () { return kids(this).find((k) => isTag(k, 'tfoot')) || null; },
      function (v) { tableSet(this, 'tfoot', v, () => null); });
    defAcc(T, 'caption', function () { return kids(this).find((k) => isTag(k, 'caption')) || null; },
      function (v) { tableSet(this, 'caption', v, (t) => kids(t)[0] || null); });
    const S = proto('HTMLTableSectionElement');
    defGet(S, 'rows', function () { return __collection(kids(this).filter((k) => isTag(k, 'tr'))); });
    const R = proto('HTMLTableRowElement');
    defGet(R, 'cells', function () { return __collection(kids(this).filter((k) => isTag(k, 'td', 'th'))); });
    defGet(R, 'rowIndex', function () {
      let t = this.parentNode;
      if (t && isTag(t, 'thead', 'tbody', 'tfoot')) t = t.parentNode;
      if (!t || !isTag(t, 'table')) return -1;
      return tableRows(t).indexOf(this);
    });
    defGet(R, 'sectionRowIndex', function () {
      const p = this.parentNode;
      if (!p || !isTag(p, 'table', 'thead', 'tbody', 'tfoot')) return -1;
      return kids(p).filter((k) => isTag(k, 'tr')).indexOf(this);
    });
    const C = proto('HTMLTableCellElement');
    defGet(C, 'cellIndex', function () {
      const p = this.parentNode;
      if (!p || !isTag(p, 'tr')) return -1;
      return kids(p).filter((k) => isTag(k, 'td', 'th')).indexOf(this);
    });
    // Список выбора.
    const selOptions = (sel) => {
      const out = [];
      for (const k of kids(sel)) {
        if (isTag(k, 'option')) out.push(k);
        else if (isTag(k, 'optgroup')) for (const o of kids(k)) if (isTag(o, 'option')) out.push(o);
      }
      return out;
    };
    const isSelected = (o) => !!(o.__ptSelected != null ? o.__ptSelected : __ptHasA(o, 'selected'));
    const SEL = proto('HTMLSelectElement');
    defGet(SEL, 'options', function () { const c = branded(selOptions(this), 'HTMLOptionsCollection'); try { Object.defineProperty(c, '__ptSelect', { value: this, configurable: true }); } catch (e) {} return c; });
    // Сеттеры selectedIndex и length, как у HTMLSelectElement/HTMLOptionsCollection Chrome.
    const selSetIndex = (sel, i) => {
      const opts = selOptions(sel); i = i | 0;
      opts.forEach((o, j) => { o.__ptSelected = (j === i); });
    };
    const selSetLength = (sel, n) => {
      const opts = selOptions(sel); n = Math.max(0, n >>> 0);
      if (n < opts.length) { for (const o of opts.slice(n)) o.parentNode && o.parentNode.removeChild(o); }
      else for (let i = opts.length; i < n; i++) sel.appendChild(sel.ownerDocument.createElement('option'));
    };
    globalThis.__pt_selSetLength = selSetLength;
    globalThis.__pt_selSetIndex = selSetIndex;
    // `value` списка — значение выбранного пункта; `selected`/`value`/`text` пункта.
    const optValue = (o) => { const v = __ptGetA(o, 'value'); return v != null ? String(v) : String(o.textContent || '').replace(/\s+/g, ' ').trim(); };
    defAcc(SEL, 'value', function () {
      const opts = selOptions(this); const multiple = __ptHasA(this, 'multiple');
      let chosen = opts.filter(isSelected);
      if (!multiple) { if (chosen.length > 1) chosen = [chosen[chosen.length - 1]]; if (!chosen.length && opts.length && __ptGetA(this, 'size') == null) chosen = [opts[0]]; }
      return chosen.length ? optValue(chosen[0]) : '';
    }, function (v) {
      const opts = selOptions(this); v = String(v); let hit = false;
      for (const o of opts) { if (!hit && optValue(o) === v) { o.__ptSelected = true; hit = true; } else o.__ptSelected = false; }
    });
    const O_ = proto('HTMLOptionElement');
    defAcc(O_, 'selected', function () { return isSelected(this); }, function (v) {
      this.__ptSelected = !!v;
      if (v) { let p = this.parentNode; if (p && isTag(p, 'optgroup')) p = p.parentNode; if (p && isTag(p, 'select') && !__ptHasA(p, 'multiple')) for (const o of selOptions(p)) if (o !== this) o.__ptSelected = false; }
    });
    defAcc(O_, 'value', function () { return optValue(this); }, function (v) { __ptSetA(this, 'value', String(v)); });
    defAcc(O_, 'text', function () { return String(this.textContent || '').replace(/\s+/g, ' ').trim(); }, function (v) { this.textContent = String(v); });
    defGet(SEL, 'selectedOptions', function () {
      const opts = selOptions(this);
      const multiple = __ptHasA(this, 'multiple');
      let chosen = opts.filter(isSelected);
      if (!multiple) { if (chosen.length > 1) chosen = [chosen[chosen.length - 1]]; if (!chosen.length && opts.length && __ptGetA(this, 'size') == null) chosen = [opts[0]]; }
      return __collection(chosen);
    });
    defAcc(SEL, 'selectedIndex', function () {
      const opts = selOptions(this);
      const multiple = __ptHasA(this, 'multiple');
      const chosen = opts.filter(isSelected);
      if (chosen.length) return opts.indexOf(multiple ? chosen[0] : chosen[chosen.length - 1]);
      return !multiple && opts.length && __ptGetA(this, 'size') == null ? 0 : -1;
    }, function (v) { selSetIndex(this, v); });
    defAcc(SEL, 'length', function () { return selOptions(this).length; }, function (v) { selSetLength(this, v); });
    defGet(SEL, 'type', function () { return __ptHasA(this, 'multiple') ? 'select-multiple' : 'select-one'; });
    defFn(SEL, 'item', function item(i) { return selOptions(this)[i | 0] || null; });
    defFn(SEL, 'namedItem', function namedItem(n) { return selOptions(this).find((o) => o.id === n || __ptGetA(o, 'name') === n) || null; });
    const DL = proto('HTMLDataListElement');
    defGet(DL, 'options', function () { const out = []; __walkTree(this, (n) => { if (isTag(n, 'option')) out.push(n); }); return __collection(out); });
    // Форма и её элементы.
    const LISTED = new Set(['button', 'fieldset', 'input', 'object', 'output', 'select', 'textarea']);
    const formOf = (el) => {
      const id = __ptGetA(el, 'form');
      if (id != null && el.ownerDocument && el.ownerDocument.getElementById) return el.ownerDocument.getElementById(id) || null;
      for (let p = el.parentNode; p; p = p.parentNode) { if (isTag(p, 'form')) return p; if (p.nodeType === 11 && p.__ptHost) { p = p.__ptHost; } }
      return null;
    };
    const formControls = (form) => {
      const out = [];
      const doc = form.ownerDocument;
      const root = doc && doc.documentElement ? doc.documentElement : form;
      __walkTree(root, (n) => {
        if (!n || n.nodeType !== ELEMENT_NODE || !LISTED.has(local(n))) return;
        if (local(n) === 'input' && String(__ptGetA(n, 'type') || '').toLowerCase() === 'image') return;
        if (formOf(n) === form) out.push(n);
      });
      return out;
    };
    const F = proto('HTMLFormElement');
    defGet(F, 'elements', function () { return branded(formControls(this), 'HTMLFormControlsCollection'); });
    defGet(F, 'length', function () { return formControls(this).length; });
    const labelsOf = (el) => {
      const out = [];
      const doc = el.ownerDocument;
      const root = doc && doc.documentElement ? doc.documentElement : null;
      if (!root) return out;
      __walkTree(root, (n) => {
        if (!isTag(n, 'label')) return;
        const f = __ptGetA(n, 'for');
        if (f != null) { if (f === el.id) out.push(n); return; }
        let found = null;
        __walkTree(n, (m) => { if (!found && m !== n && m.nodeType === ELEMENT_NODE && LABELABLE.has(local(m)) && !(local(m) === 'input' && String(__ptGetA(m, 'type') || '').toLowerCase() === 'hidden')) found = m; });
        if (found === el) out.push(n);
      });
      return out;
    };
    const LABELABLE = new Set(['button', 'input', 'meter', 'output', 'progress', 'select', 'textarea']);
    for (const n of ['HTMLButtonElement', 'HTMLInputElement', 'HTMLMeterElement', 'HTMLOutputElement', 'HTMLProgressElement', 'HTMLSelectElement', 'HTMLTextAreaElement']) {
      const P = proto(n);
      defGet(P, 'labels', function () {
        if (local(this) === 'input' && String(__ptGetA(this, 'type') || '').toLowerCase() === 'hidden') return null;
        return __staticNodeList(labelsOf(this));
      });
    }
    for (const n of ['HTMLButtonElement', 'HTMLInputElement', 'HTMLOutputElement', 'HTMLSelectElement', 'HTMLTextAreaElement', 'HTMLFieldSetElement', 'HTMLObjectElement', 'HTMLLabelElement', 'HTMLLegendElement']) {
      const P = proto(n);
      defGet(P, 'form', function () {
        if (local(this) === 'legend') { const p = this.parentNode; return p && isTag(p, 'fieldset') ? formOf(p) : null; }
        if (local(this) === 'label') { const c = this.control; return c ? formOf(c) : null; }
        return formOf(this);
      });
    }
    const L = proto('HTMLLabelElement');
    defGet(L, 'control', function () {
      const f = __ptGetA(this, 'for');
      if (f != null) { const el = this.ownerDocument && this.ownerDocument.getElementById ? this.ownerDocument.getElementById(f) : null; return el && LABELABLE.has(local(el)) ? el : null; }
      let found = null;
      __walkTree(this, (m) => { if (!found && m !== this && m.nodeType === ELEMENT_NODE && LABELABLE.has(local(m)) && !(local(m) === 'input' && String(__ptGetA(m, 'type') || '').toLowerCase() === 'hidden')) found = m; });
      return found;
    });
    const M = proto('HTMLMapElement');
    defGet(M, 'areas', function () { const out = []; __walkTree(this, (n) => { if (isTag(n, 'area')) out.push(n); }); return __collection(out); });
    const O = proto('HTMLOptionElement');
    defGet(O, 'index', function () { let p = this.parentNode; if (p && isTag(p, 'optgroup')) p = p.parentNode; return p && isTag(p, 'select') ? selOptions(p).indexOf(this) : 0; });
  }
  globalThis.__pt_elementProto = (tag) => {
    tag = String(tag).toLowerCase();
    const iface = TAG_IFACE[tag];
    if (iface) return __ifaceProto.get(iface) || __htmlProto;
    if (PLAIN_TAGS.has(tag)) return __htmlProto;
    // Всё, чего в HTML нет, — HTMLUnknownElement, как у браузера.
    return /^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(tag) ? __htmlProto : __ifaceProto.get('HTMLUnknownElement');
  };
  globalThis.__pt_setPendingTag = (tag) => { __pendingTag = String(tag || 'div'); };
  // `sheet` — таблица стилей самого элемента, та же, что лежит в
  // `document.styleSheets`. Мы построили список, но с элементом его не связали,
  // а читают чаще именно так: `document.querySelector('style').sheet.cssRules`.
  for (const iface of ['HTMLStyleElement', 'HTMLLinkElement']) {
    const proto = globalThis[iface] && globalThis[iface].prototype;
    if (!proto) continue;
    Object.defineProperty(proto, 'sheet', {
      get() {
        if (this.__ptLocal === 'link' && !__ptHasSheet(this)) return null;
        if (!this.isConnected) return null;
        return globalThis.__pt_sheetFor ? __pt_sheetFor(this) : null;
      },
      enumerable: true, configurable: true,
    });
  }
  // `complete` истинно, когда грузить нечего или загрузка уже завершилась —
  // и ложно, пока она в полёте. Мы отвечали «истина» всегда, в том числе сразу
  // после присвоения `src`, чего браузер не делает: там сначала `false`, а
  // `true` приходит вместе с событием.
  {
    const proto = globalThis.HTMLImageElement && HTMLImageElement.prototype;
    if (proto) {
      Object.defineProperty(proto, 'complete', {
        get() {
          const src = __ptGetA(this, 'src');
          if (!src) return true;
          return !!this.__ptImgDone;
        },
        enumerable: true, configurable: true,
      });
    }
  }
  // Члены HTMLTemplateElement, снятые с Chrome 148. `content` — сам фрагмент,
  // остальные отражают атрибуты объявленного теневого корня.
  {
    const proto = globalThis.HTMLTemplateElement && HTMLTemplateElement.prototype;
    if (proto) {
      Object.defineProperty(proto, 'content', {
        get() { return globalThis.__pt_templateContent ? __pt_templateContent(this) : null; },
        enumerable: true, configurable: true,
      });
      const attr = (name, want) => Object.defineProperty(proto, name, {
        get() { const v = __ptGetA(this, want); return v === null ? (want === 'shadowrootmode' ? '' : false) : (want === 'shadowrootmode' ? v : true); },
        set(v) { if (want === 'shadowrootmode') __ptSetA(this, want, String(v)); else if (v) __ptSetA(this, want, ''); else __ptDelA(this, want); },
        enumerable: true, configurable: true,
      });
      attr('shadowRootMode', 'shadowrootmode');
      attr('shadowRootDelegatesFocus', 'shadowrootdelegatesfocus');
      attr('shadowRootClonable', 'shadowrootclonable');
      attr('shadowRootSerializable', 'shadowrootserializable');
      Object.defineProperty(proto, 'shadowRootCustomElementRegistry', {
        get() { return ''; }, set() {}, enumerable: true, configurable: true,
      });
    }
  }
  // Ссылка на прототип холста переживает обрезку глобалей воркерной области:
  // OffscreenCanvas берёт методы отсюда, когда документа нет.
  try {
    Object.defineProperty(globalThis, '__pt_canvasProto', {
      value: globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype,
      enumerable: false, configurable: true, writable: true,
    });
  } catch (e) {}
  // SVG — своя лестница, и она глубже HTML: `<path>` это SVGPathElement →
  // SVGGeometryElement → SVGGraphicsElement → SVGElement → Element. У нас любой
  // `createElementNS('…/svg', 'path')` был HTMLUnknownElement, и виджет, который
  // рисует свою галочку из path/line/circle, отдавал сборщику чужие имена.
  // Цепочки сняты с Chrome 148.
  const SVG_CHAIN = {"svg":["SVGSVGElement","SVGGraphicsElement","SVGElement"],"path":["SVGPathElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"line":["SVGLineElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"circle":["SVGCircleElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"g":["SVGGElement","SVGGraphicsElement","SVGElement"],"rect":["SVGRectElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"text":["SVGTextElement","SVGTextPositioningElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"tspan":["SVGTSpanElement","SVGTextPositioningElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"defs":["SVGDefsElement","SVGGraphicsElement","SVGElement"],"use":["SVGUseElement","SVGGraphicsElement","SVGElement"],"polygon":["SVGPolygonElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"polyline":["SVGPolylineElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"ellipse":["SVGEllipseElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"image":["SVGImageElement","SVGGraphicsElement","SVGElement"],"clipPath":["SVGClipPathElement","SVGElement"],"mask":["SVGMaskElement","SVGElement"],"pattern":["SVGPatternElement","SVGElement"],"filter":["SVGFilterElement","SVGElement"],"marker":["SVGMarkerElement","SVGElement"],"symbol":["SVGSymbolElement","SVGGraphicsElement","SVGElement"],"title":["SVGTitleElement","SVGElement"],"desc":["SVGDescElement","SVGElement"],"style":["SVGStyleElement","SVGElement"],"a":["SVGAElement","SVGGraphicsElement","SVGElement"],"foreignObject":["SVGForeignObjectElement","SVGGraphicsElement","SVGElement"],"linearGradient":["SVGLinearGradientElement","SVGGradientElement","SVGElement"],"radialGradient":["SVGRadialGradientElement","SVGGradientElement","SVGElement"],"stop":["SVGStopElement","SVGElement"],"animate":["SVGAnimateElement","SVGAnimationElement","SVGElement"],"textPath":["SVGTextPathElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"switch":["SVGSwitchElement","SVGGraphicsElement","SVGElement"],"metadata":["SVGMetadataElement","SVGElement"],"view":["SVGViewElement","SVGElement"],"set":["SVGSetElement","SVGAnimationElement","SVGElement"],"script":["SVGScriptElement","SVGElement"]};
  {
    const svgProto = new Map();
    // Строим снизу вверх: каждая ступень наследует следующей за ней в цепочке.
    const protoFor = (chain, i) => {
      const name = chain[i];
      if (svgProto.has(name)) return svgProto.get(name);
      const parent = i + 1 < chain.length ? protoFor(chain, i + 1) : Element.prototype;
      const proto = __mkIface(name, parent);
      svgProto.set(name, proto);
      return proto;
    };
    for (const chain of Object.values(SVG_CHAIN)) protoFor(chain, 0);
    // Промежуточные интерфейсы, которых нет первым звеном ни у одного тега.
    for (const n of ['SVGGeometryElement', 'SVGGraphicsElement', 'SVGElement',
                     'SVGTextPositioningElement', 'SVGTextContentElement',
                     'SVGGradientElement', 'SVGAnimationElement', 'SVGComponentTransferFunctionElement']) {
      if (!svgProto.has(n)) svgProto.set(n, __mkIface(n, svgProto.get('SVGElement') || Element.prototype));
    }
    globalThis.__pt_svgProto = (tag) => svgProto.get((SVG_CHAIN[tag] || [])[0]) ||
                                        svgProto.get('SVGElement') || null;
    // По имени интерфейса, а не тега: измерительные члены должны лечь на
    // `SVGTextContentElement`, а не на общий `SVGElement`, — страница ходит по
    // цепочке прототипов и видит, у кого что лежит.
    globalThis.__pt_svgIface = (name) => svgProto.get(name) || null;
  }


  // Измерительные члены SVG. Интерфейсы у нас были правильные, а методов не
  // было ни одного: `getBBox`, `getTotalLength`, `getPointAtLength`,
  // `getScreenCTM`, `circle.cx` — всё бросало или отдавало пустоту. Это
  // отдельный измерительный тракт, и им тоже снимают отпечаток: текст меряют
  // не только холстом, но и рамкой `<text>`.
  {
    const P = (n) => (globalThis.__pt_svgIface && __pt_svgIface(n))
      || (globalThis.__pt_svgProto ? __pt_svgProto(n) : null);
    const wrap = (name, val) => {
      const C = globalThis[name];
      const o = C && C.prototype ? Object.create(C.prototype) : {};
      try {
        if (C && C.prototype && !Object.getOwnPropertyDescriptor(C.prototype, Symbol.toStringTag)) {
          Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true });
        }
      } catch (e) {}
      for (const [k, v] of Object.entries(val)) {
        Object.defineProperty(o, k, { value: v, enumerable: true, configurable: true, writable: true });
      }
      return o;
    };
    const svgLength = (v) => wrap('SVGLength', {
      unitType: 1, value: v, valueInSpecifiedUnits: v, valueAsString: String(v),
      newValueSpecifiedUnits() {}, convertToSpecifiedUnits() {},
    });
    const animLength = (get) => wrap('SVGAnimatedLength', {
      get baseVal() { return svgLength(get()); },
      get animVal() { return svgLength(get()); },
    });
    const svgRect = (x, y, w, h) => wrap('SVGRect', { x, y, width: w, height: h });
    const svgPoint = (x, y) => wrap('SVGPoint', { x, y, matrixTransform() { return svgPoint(x, y); } });
    const svgMatrix = () => wrap('SVGMatrix', {
      a: 1, b: 0, c: 0, d: 1, e: 0, f: 0,
      multiply() { return svgMatrix(); }, inverse() { return svgMatrix(); },
      translate() { return svgMatrix(); }, scale() { return svgMatrix(); },
      rotate() { return svgMatrix(); }, flipX() { return svgMatrix(); }, flipY() { return svgMatrix(); },
      skewX() { return svgMatrix(); }, skewY() { return svgMatrix(); },
      scaleNonUniform() { return svgMatrix(); }, rotateFromVector() { return svgMatrix(); },
    });
    const num = (el, name, dflt) => {
      const v = parseFloat(el.getAttribute && __ptGetA(el, name));
      return Number.isFinite(v) ? v : (dflt || 0);
    };

    // Разбор атрибута `d`: точки контура, по которым считаются и рамка, и
    // длина. Кривые разбиваются на отрезки — так же поступает и браузер, только
    // с меньшим шагом.
    const pathPoints = (d) => {
      const out = [];
      const toks = String(d || '').match(/[MmLlHhVvCcSsQqTtAaZz]|-?[\d.]+(?:e-?\d+)?/g) || [];
      let i = 0, x = 0, y = 0, sx = 0, sy = 0, cmd = '';
      const n = () => parseFloat(toks[i++]) || 0;
      const push = (px, py) => out.push([px, py]);
      const bez = (x0, y0, x1, y1, x2, y2, x3, y3) => {
        for (let t = 1; t <= 16; t++) {
          const u = t / 16, m = 1 - u;
          push(m*m*m*x0 + 3*m*m*u*x1 + 3*m*u*u*x2 + u*u*u*x3,
               m*m*m*y0 + 3*m*m*u*y1 + 3*m*u*u*y2 + u*u*u*y3);
        }
      };
      while (i < toks.length) {
        if (/[A-Za-z]/.test(toks[i])) cmd = toks[i++];
        const rel = cmd === cmd.toLowerCase();
        const C = cmd.toUpperCase();
        if (C === 'M') { const a = n(), b = n(); x = rel ? x + a : a; y = rel ? y + b : b; sx = x; sy = y; push(x, y); cmd = rel ? 'l' : 'L'; }
        else if (C === 'L') { const a = n(), b = n(); x = rel ? x + a : a; y = rel ? y + b : b; push(x, y); }
        else if (C === 'H') { const a = n(); x = rel ? x + a : a; push(x, y); }
        else if (C === 'V') { const a = n(); y = rel ? y + a : a; push(x, y); }
        else if (C === 'C') {
          const x1 = n(), y1 = n(), x2 = n(), y2 = n(), x3 = n(), y3 = n();
          const ax1 = rel ? x + x1 : x1, ay1 = rel ? y + y1 : y1;
          const ax2 = rel ? x + x2 : x2, ay2 = rel ? y + y2 : y2;
          const ax3 = rel ? x + x3 : x3, ay3 = rel ? y + y3 : y3;
          bez(x, y, ax1, ay1, ax2, ay2, ax3, ay3); x = ax3; y = ay3;
        } else if (C === 'Q') {
          const x1 = n(), y1 = n(), x2 = n(), y2 = n();
          const ax1 = rel ? x + x1 : x1, ay1 = rel ? y + y1 : y1;
          const ax2 = rel ? x + x2 : x2, ay2 = rel ? y + y2 : y2;
          bez(x, y, x + 2/3*(ax1-x), y + 2/3*(ay1-y), ax2 + 2/3*(ax1-ax2), ay2 + 2/3*(ay1-ay2), ax2, ay2);
          x = ax2; y = ay2;
        } else if (C === 'Z') { push(sx, sy); x = sx; y = sy; }
        else { i++; }
      }
      return out;
    };

    const boxOfPoints = (pts) => {
      if (!pts.length) return [0, 0, 0, 0];
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const [px, py] of pts) { x0 = Math.min(x0, px); y0 = Math.min(y0, py); x1 = Math.max(x1, px); y1 = Math.max(y1, py); }
      return [x0, y0, x1 - x0, y1 - y0];
    };
    const lenOfPoints = (pts) => {
      let L = 0;
      for (let k = 1; k < pts.length; k++) L += Math.hypot(pts[k][0] - pts[k-1][0], pts[k][1] - pts[k-1][1]);
      return L;
    };
    const outline = (el) => {
      const t = (el.localName || '').toLowerCase();
      if (t === 'path') return pathPoints(__ptGetA(el, 'd'));
      if (t === 'line') return [[num(el, 'x1'), num(el, 'y1')], [num(el, 'x2'), num(el, 'y2')]];
      if (t === 'rect') { const x = num(el, 'x'), y = num(el, 'y'), w = num(el, 'width'), h = num(el, 'height');
        return [[x, y], [x + w, y], [x + w, y + h], [x, y + h], [x, y]]; }
      if (t === 'circle') { const cx = num(el, 'cx'), cy = num(el, 'cy'), r = num(el, 'r');
        return [[cx - r, cy - r], [cx + r, cy + r]]; }
      if (t === 'ellipse') { const cx = num(el, 'cx'), cy = num(el, 'cy'), rx = num(el, 'rx'), ry = num(el, 'ry');
        return [[cx - rx, cy - ry], [cx + rx, cy + ry]]; }
      if (t === 'polyline' || t === 'polygon') {
        const nums = String(__ptGetA(el, 'points') || '').match(/-?[\d.]+/g) || [];
        const pts = []; for (let k = 0; k + 1 < nums.length; k += 2) pts.push([+nums[k], +nums[k+1]]);
        return pts;
      }
      return [];
    };

    const graphics = P('SVGGraphicsElement');
    const geometry = P('SVGGeometryElement');
    const textContent = P('SVGTextContentElement');
    const def = (proto, name, value) => {
      if (!proto) return;
      try { Object.defineProperty(proto, name, { value, writable: true, enumerable: true, configurable: true }); } catch (e) {}
    };
    const acc = (proto, name, get) => {
      if (!proto) return;
      try { Object.defineProperty(proto, name, { get, enumerable: true, configurable: true }); } catch (e) {}
    };

    def(graphics, 'getBBox', function getBBox() {
      // Рамку спрашивают у разложенного дерева: без этого правила таблиц
      // ещё не собраны, и текст меряется не той гарнитурой.
      __relayout();
      const t = (this.localName || '').toLowerCase();
      if (t === 'text' || t === 'tspan') {
        // Рамка текста: ширина — измеренная и округлённая вверх до
        // шестьдесят четвёртой пикселя, подъём и высота — из метрик гарнитуры.
        // Проверено на трёх кеглях.
        // Кегль и гарнитура берутся из каскада, а не из вычисленного стиля:
        // тот строит все четыре с лишним сотни свойств, и рамка одного
        // `<text>` обходилась в восьмую долю секунды.
        if (!__svgLaidOut(this)) return svgRect(0, 0, 0, 0);
        const s = __svgScale(this);
        const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
        const { fam, bold, italic } = __svgFont(this);
        // Рамка — объединение двух: коробки чернил и коробки раскладки.
        // Вправо берётся дальняя из них (у «W» чернила вылезают за ширину
        // знака), влево — только если чернила уходят левее начала («jjj» у
        // Arial начинается на пиксель левее). Проверено на пяти сочетаниях
        // гарнитуры с кеглем.
        const txt = __svgText(this);
        // Текста нет — и рамки нет: браузер отдаёт нули, а не полоску высотой
        // в строку.
        if (!txt) return svgRect(0, 0, 0, 0);
        // Текст под преобразованием браузер раскладывает в кегле, умноженном
        // на масштаб (усечённом до сотых), ширину округляет вверх до 1/64, а
        // потом делит обратно — в одинарной точности.
        const m = __textMetrics(txt, fs, fam, bold, italic);
        const adv = m[0] || 0;
        const over = Math.max(m[1] || 0, 0);
        const w = over + Math.ceil(Math.max(m[2] || 0, adv) * 64) / 64;
        const { asc, desc } = __svgAscDesc(txt, fs, fam);
        const x = num(this, 'x'), y = num(this, 'y');
        if (s === 1) return svgRect(x - over, y - asc, w, asc + desc);
        // Обратно из масштабированного пространства браузер идёт умножением
        // на обратный масштаб в одинарной точности, а не делением.
        const fr = Math.fround;
        const s32 = fr(s), inv = fr(1 / s32);
        return svgRect(fr(fr(fr(x * s32) - over) * inv), fr(fr(fr(y * s32) - asc) * inv), fr(w * inv), fr((asc + desc) * inv));
      }
      const kids = [...(this.__ptKids || [])].filter((k) => k.nodeType === ELEMENT_NODE);
      if (!outline(this).length && kids.length) {
        // Рамка группы — объединение рамок детей, каждая в её собственном
        // преобразовании; числа одинарной точности, как у браузера.
        const fr = Math.fround;
        let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
        for (const k of kids) {
          if (!k.getBBox) continue;
          const b = k.getBBox();
          let bx = b.x, by = b.y, bw = b.width, bh = b.height;
          const M = __svgOwnMatrix(k);
          if (M) {
            const pts = [[bx, by], [bx + bw, by], [bx, by + bh], [bx + bw, by + bh]]
              .map(([px, py]) => [fr(M[0] * px + M[2] * py + M[4]), fr(M[1] * px + M[3] * py + M[5])]);
            const xs = pts.map((q) => q[0]), ys = pts.map((q) => q[1]);
            bx = Math.min(...xs); by = Math.min(...ys); bw = fr(Math.max(...xs) - bx); bh = fr(Math.max(...ys) - by);
          }
          x0 = Math.min(x0, bx); y0 = Math.min(y0, by);
          x1 = Math.max(x1, fr(bx + bw)); y1 = Math.max(y1, fr(by + bh));
        }
        if (x0 !== Infinity) return svgRect(x0, y0, fr(x1 - x0), fr(y1 - y0));
      }
      const [x, y, w, h] = boxOfPoints(outline(this));
      return svgRect(x, y, w, h);
    });
    def(graphics, 'getCTM', function getCTM() { return svgMatrix(); });
    def(graphics, 'getScreenCTM', function getScreenCTM() { return svgMatrix(); });
    def(geometry, 'getTotalLength', function getTotalLength() { return lenOfPoints(outline(this)); });
    def(geometry, 'getPointAtLength', function getPointAtLength(at) {
      const pts = outline(this);
      let left = Math.max(0, +at || 0);
      for (let k = 1; k < pts.length; k++) {
        const dx = pts[k][0] - pts[k-1][0], dy = pts[k][1] - pts[k-1][1];
        const seg = Math.hypot(dx, dy);
        if (left <= seg || k === pts.length - 1) {
          const u = seg ? left / seg : 0;
          return svgPoint(pts[k-1][0] + dx * u, pts[k-1][1] + dy * u);
        }
        left -= seg;
      }
      return svgPoint(pts.length ? pts[0][0] : 0, pts.length ? pts[0][1] : 0);
    });
    def(geometry, 'isPointInFill', function isPointInFill(pt) {
      const [x, y, w, h] = boxOfPoints(outline(this));
      const px = pt && pt.x || 0, py = pt && pt.y || 0;
      return px >= x && px <= x + w && py >= y && py <= y + h;
    });
    def(geometry, 'isPointInStroke', function isPointInStroke(pt) { return this.isPointInFill(pt); });
    acc(geometry, 'pathLength', function pathLength() { return animLength(() => num(this, 'pathLength')); });
    // Длина строки — это её ширина при раскладке, а не рамка: у рамки бывают
    // чернила шире знака, и тогда числа расходятся.
    // Гарнитура и начертание текста SVG — из каскада, а без них — то, что у
    // документа по умолчанию (Times New Roman у Chrome), а не sans-serif.
    const __svgFont = (el) => {
      const c = __cascadeFor(el);
      let famRaw = c.get('font-family');
      if (famRaw == null) famRaw = __inheritedValue(el, 'font-family');
      const fam = String(famRaw || '').trim() || String((typeof CS_BASE !== 'undefined' && CS_BASE['font-family']) || '"Times New Roman"');
      let st = c.get('font-style'); if (st == null) st = __inheritedValue(el, 'font-style');
      let wt = c.get('font-weight'); if (wt == null) wt = __inheritedValue(el, 'font-weight');
      const italic = /^(italic|oblique)/i.test(String(st || ''));
      const w = String(wt || '').toLowerCase();
      const bold = w === 'bold' || w === 'bolder' || (Number(w) >= 600);
      return { fam, bold, italic };
    };
    // Масштаб текста: произведение равномерных масштабов преобразований
    // самого элемента и предков до корня svg — так браузер выбирает кегль
    // раскладки (`CalculateScreenFontSizeScalingFactor`).
    const __svgOwnMatrix = (n) => {
      let t = null;
      try { t = __cascadeFor(n).get('transform'); } catch (e) {}
      if (t == null) t = __ptGetA(n, 'transform');
      return __parseTransform(t);
    };
    const __svgOwnScale = (n) => {
      const M = __svgOwnMatrix(n);
      if (!M) return 1;
      const sc = Math.sqrt((M[0] * M[0] + M[1] * M[1] + M[2] * M[2] + M[3] * M[3]) / 2);
      return isFinite(sc) && sc > 0 ? sc : 1;
    };
    const __svgScale = (el) => {
      let s = 1;
      for (let n = el; n && n.nodeType === ELEMENT_NODE; n = n.parentNode) {
        s *= __svgOwnScale(n);
        if (n.__ptLocal === 'svg') break;
      }
      return s;
    };
    const __svgSizeEff = (fs, s) => (s === 1 ? fs : Math.floor(fs * s * 100 + 1e-7) / 100);
    // Подъём и спуск строки — из гарнитуры прогона: эмодзи набираются Noto
    // Color Emoji, и рамка у них по её метрикам (1900/512 на 2048).
    const EMOJI_RE = /\p{Extended_Pictographic}/u;
    const __svgAscDesc = (txt, fs, fam) => {
      const fb = __fontBox(fs, fam);
      let asc = fb.asc, desc = fb.desc;
      if (EMOJI_RE.test(txt)) {
        const rest = txt.replace(/\p{Extended_Pictographic}|\uFE0F|\u200D|[\u{1F3FB}-\u{1F3FF}]|\s/gu, '');
        // У растровой гарнитуры эмодзи подъём и спуск — это границы самой
        // картинки: то же, что actualBoundingBox у холста (15/4 на 16px,
        // 23/6 на 24px, 139/38 на 150px).
        const m = __textMetrics(txt, fs, fam, false, false);
        const ea = Math.round(m[3] || fs * 1900 / 2048), ed = Math.round(m[4] || fs * 512 / 2048);
        if (!rest) { asc = ea; desc = ed; } else { asc = Math.max(asc, ea); desc = Math.max(desc, ed); }
      }
      return { asc, desc };
    };
    // Без раскладки (документ без окна, оторванный узел, дитя хозяина без
    // слота) длины и рамки у браузера нулевые.
    const __svgLaidOut = (el) => {
      if (!el || !el.isConnected) return false;
      if (el.ownerDocument && el.ownerDocument !== document && !el.ownerDocument.defaultView) return false;
      if (typeof globalThis.__pt_inFlatTree === 'function' && !globalThis.__pt_inFlatTree(el)) return false;
      return true;
    };
    def(textContent, 'getComputedTextLength', function getComputedTextLength() {
      __relayout();
      if (!__svgLaidOut(this)) return 0;
      const s = __svgScale(this);
      const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
      const { fam, bold, italic } = __svgFont(this);
      const txt = __svgText(this);
      if (!txt) return 0;
      const w = Math.ceil(__textWidth(txt, fs, fam, bold, italic) * 64) / 64;
      // Длина — деление на масштаб в одинарной точности (рамка, напротив,
      // умножается на обратный: у браузера это два разных пути).
      return s === 1 ? w : Math.fround(w / Math.fround(s));
    });
    def(textContent, 'getSubStringLength', function getSubStringLength(start, n) {
      __relayout();
      if (!__svgLaidOut(this)) return 0;
      const s = __svgScale(this);
      const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
      const { fam, bold, italic } = __svgFont(this);
      const full = __svgText(this);
      const from = Math.max(0, start | 0), len = Math.max(0, n | 0);
      const txt = full.slice(from, from + len);
      if (!txt) return 0;
      const w = Math.ceil(__textWidth(txt, fs, fam, bold, italic) * 64) / 64;
      // Длина — деление на масштаб в одинарной точности (рамка, напротив,
      // умножается на обратный: у браузера это два разных пути).
      return s === 1 ? w : Math.fround(w / Math.fround(s));
    });
    // Протяжённость знака: рамка строки гарнитуры элемента (подъём и спуск
    // основного шрифта) шириной в продвижение самого знака.
    def(textContent, 'getExtentOfChar', function getExtentOfChar(i) {
      __relayout();
      if (!__svgLaidOut(this)) return svgRect(0, 0, 0, 0);
      const s = __svgScale(this);
      const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
      const { fam, bold, italic } = __svgFont(this);
      const full = __svgText(this);
      let idx = Number(i); if (!isFinite(idx) || idx < 0) idx = 0; idx = Math.floor(idx);
      if (!full || idx >= full.length) {
        throw new (globalThis.DOMException || Error)("Failed to execute 'getExtentOfChar' on 'SVGTextContentElement': The index provided (" + idx + ") is outside the range of characters.", 'IndexSizeError');
      }
      // Знак — вместе с парным суррогатом и модификаторами: у эмодзи одно
      // продвижение на всю последовательность.
      const cps = Array.from(full);
      let at = 0, ci = 0;
      for (; ci < cps.length && at + cps[ci].length <= idx; ci++) at += cps[ci].length;
      const before = full.slice(0, at);
      const ch = full.slice(at, at + (cps[ci] ? cps[ci].length : 1)) || full.slice(at, at + 1);
      const wAll = __textWidth(before + ch, fs, fam, bold, italic), wBefore = before ? __textWidth(before, fs, fam, bold, italic) : 0;
      const adv = Math.ceil(Math.max(0, wAll - wBefore) * 64) / 64;
      const fb = __fontBox(fs, fam);
      const x = num(this, 'x') + wBefore, y = num(this, 'y');
      if (s === 1) return svgRect(x, y - fb.asc, adv, fb.asc + fb.desc);
      const fr = Math.fround; const s32 = fr(s), inv = fr(1 / s32);
      return svgRect(fr(fr(x * s32) * inv), fr(fr(fr(y * s32) - fb.asc) * inv), fr(adv / s32), fr((fb.asc + fb.desc) * inv));
    });
    def(textContent, 'getNumberOfChars', function getNumberOfChars() { return String(this.textContent || '').length; });

    // Геометрические атрибуты — не строки, а `SVGAnimatedLength`.
    const GEOM_ATTRS = {
      SVGCircleElement: ['cx', 'cy', 'r'],
      SVGEllipseElement: ['cx', 'cy', 'rx', 'ry'],
      SVGRectElement: ['x', 'y', 'width', 'height', 'rx', 'ry'],
      SVGLineElement: ['x1', 'y1', 'x2', 'y2'],
      SVGSVGElement: ['x', 'y', 'width', 'height'],
      SVGImageElement: ['x', 'y', 'width', 'height'],
      SVGTextPositioningElement: ['x', 'y', 'dx', 'dy'],
    };
    for (const [iface, attrs] of Object.entries(GEOM_ATTRS)) {
      const proto = P(iface) || (globalThis[iface] && globalThis[iface].prototype);
      for (const a of attrs) acc(proto, a, function () { return animLength(() => num(this, a)); });
    }
    const svgEl = P('SVGSVGElement');
    acc(svgEl, 'viewBox', function viewBox() {
      const n = String(__ptGetA(this, 'viewBox') || '').match(/-?[\d.]+/g) || [];
      const r = svgRect(+n[0] || 0, +n[1] || 0, +n[2] || 0, +n[3] || 0);
      return wrap('SVGAnimatedRect', { baseVal: r, animVal: r });
    });
    def(svgEl, 'createSVGPoint', function createSVGPoint() { return svgPoint(0, 0); });
    def(svgEl, 'createSVGRect', function createSVGRect() { return svgRect(0, 0, 0, 0); });
    def(svgEl, 'createSVGMatrix', function createSVGMatrix() { return svgMatrix(); });
    def(svgEl, 'createSVGLength', function createSVGLength() { return svgLength(0); });
  }

  // Опрос кодеков — стандартный блок отпечатка, и он идёт в отчёт челленджа
  // целиком. Прежнее правило («известный контейнер плюс известный кодек —
  // significa probably») было втрое шире браузерного: Chrome сверяет кодек
  // именно с контейнером, и 220 ответов из 597 у нас расходились. Таблица
  // снята с Chrome 151 на этой машине перебором 597 строк; `audio/mpeg`,
  // `audio/aac` и `audio/flac` сами себе кодек, поэтому без списка кодеков
  // отвечают `probably`, остальные известные — `maybe`.
  {
    const FAMILY = {
      'video/mp4': ['avc1.', 'avc3.', 'hev1.', 'hvc1.', 'av01.', 'vp09.', 'mp4a.40.',
                    'mp4a.69', 'mp4a.6b', 'mp3', 'opus', 'flac'],
      'video/webm': ['vp8', 'vp9', 'vp09.', 'av01.', 'opus', 'vorbis'],
      'video/ogg': ['vp8', 'opus', 'vorbis', 'flac'],
      'video/3gpp': ['avc1.', 'avc3.', 'mp4a.40.'],
      'video/x-matroska': ['avc1.', 'avc3.', 'hev1.', 'hvc1.', 'av01.', 'vp8', 'vp09.',
                           'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3', 'opus', 'vorbis', 'flac', '1'],
      'application/x-mpegurl': ['avc1.', 'avc3.', 'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3'],
      'application/vnd.apple.mpegurl': ['avc1.', 'avc3.', 'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3'],
      'audio/mp4': ['mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3', 'opus', 'flac'],
      'audio/ogg': ['opus', 'vorbis', 'flac'],
      'audio/webm': ['opus', 'vorbis'],
      'audio/wav': ['1'],
      'audio/x-wav': ['1'],
      'audio/x-m4a': ['mp4a.40.'],
      'audio/mpeg': ['mp3', 'mp4a.69', 'mp4a.6b'],
      'audio/aac': [],
      'audio/flac': [],
    };
    // Эти типы сами себе кодек: контейнер и содержимое одно и то же.
    const SINGLE = new Set(['audio/mpeg', 'audio/aac', 'audio/flac']);
    const canPlay = function canPlayType(type) {
      const t = String(type == null ? '' : type).trim();
      const semi = t.indexOf(';');
      const mime = (semi < 0 ? t : t.slice(0, semi)).trim().toLowerCase();
      const rest = semi < 0 ? '' : t.slice(semi + 1);
      const m = /codecs\s*=\s*"?([^"]*)"?/i.exec(rest);
      const codecs = m ? m[1].split(',').map((c) => c.trim().toLowerCase()).filter(Boolean) : [];
      const allowed = FAMILY[mime];
      if (!allowed) return '';
      if (!codecs.length) return SINGLE.has(mime) ? 'probably' : 'maybe';
      const fits = (c) => allowed.some((a) => (a.charAt(a.length - 1) === '.' ? c.indexOf(a) === 0 : c === a));
      return codecs.every(fits) ? 'probably' : '';
    };
    const M = globalThis.HTMLMediaElement && globalThis.HTMLMediaElement.prototype;
    if (M) {
      try { Object.defineProperty(M, 'canPlayType', { value: canPlay, writable: true, enumerable: true, configurable: true }); } catch (e) {}
    }
    // Джойстики: браузер отдаёт четыре пустых гнезда, а не пустоту. Заглушка
    // возвращала `undefined`, и всякий, кто читал `.length`, получал исключение.
    const N = globalThis.Navigator && globalThis.Navigator.prototype;
    if (N) {
      const fn = function getGamepads() { return [null, null, null, null]; };
      try {
        Object.defineProperty(N, 'getGamepads', {
          value: globalThis.__pt_native ? __pt_native(fn) : fn,
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
    // `MediaSource.isTypeSupported` отвечает тем же знанием, только логическим.
    const MS = globalThis.MediaSource;
    if (MS) {
      try {
        Object.defineProperty(MS, 'isTypeSupported', {
          value: function isTypeSupported(type) { return canPlay(type) === 'probably'; },
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
  }

  // `hidden` — отражаемый атрибут HTMLElement: мы его читали внутри себя, но
  // наружу не отдавали вовсе, хотя в браузере он есть у каждого элемента.
  Object.defineProperty(__htmlProto, 'hidden', {
    get() { return __ptHasA(this, 'hidden'); },
    set(v) { if (v) __ptSetA(this, 'hidden', ''); else __ptDelA(this, 'hidden'); },
    enumerable: true, configurable: true,
  });

  // Развес членов по ступеням — списки сняты с Chrome 148. Наши реализации
  // универсальны (читают атрибуты), поэтому член, который в браузере есть у
  // нескольких интерфейсов, кладётся на каждый из них тем же дескриптором.
const CHROME_ELEMENT = ["activeViewTransition","after","animate","append","ariaActiveDescendantElement","ariaAtomic","ariaAutoComplete","ariaBrailleLabel","ariaBrailleRoleDescription","ariaBusy","ariaChecked","ariaColCount","ariaColIndex","ariaColIndexText","ariaColSpan","ariaControlsElements","ariaCurrent","ariaDescribedByElements","ariaDescription","ariaDetailsElements","ariaDisabled","ariaErrorMessageElements","ariaExpanded","ariaFlowToElements","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLabelledByElements","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaNotify","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowIndexText","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","assignedSlot","attachShadow","attributes","before","checkVisibility","childElementCount","children","classList","className","clientHeight","clientLeft","clientTop","clientWidth","closest","computedStyleMap","currentCSSZoom","customElementRegistry","elementTiming","firstElementChild","getAnimations","getAttribute","getAttributeNS","getAttributeNames","getAttributeNode","getAttributeNodeNS","getBoundingClientRect","getClientRects","getElementsByClassName","getElementsByTagName","getElementsByTagNameNS","getHTML","hasAttribute","hasAttributeNS","hasAttributes","hasPointerCapture","id","innerHTML","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","lastElementChild","localName","matches","moveBefore","namespaceURI","nextElementSibling","onbeforecopy","onbeforecut","onbeforepaste","onfullscreenchange","onfullscreenerror","onsearch","onwebkitfullscreenchange","onwebkitfullscreenerror","outerHTML","part","prefix","prepend","previousElementSibling","querySelector","querySelectorAll","releasePointerCapture","remove","removeAttribute","removeAttributeNS","removeAttributeNode","replaceChildren","replaceWith","requestFullscreen","requestPointerLock","role","scroll","scrollBy","scrollHeight","scrollIntoView","scrollIntoViewIfNeeded","scrollLeft","scrollTo","scrollTop","scrollWidth","setAttribute","setAttributeNS","setAttributeNode","setAttributeNodeNS","setHTML","setHTMLUnsafe","setPointerCapture","shadowRoot","slot","startViewTransition","tagName","toggleAttribute","webkitMatchesSelector","webkitRequestFullScreen","webkitRequestFullscreen"];
const CHROME_HTMLELEMENT = ["accessKey","attachInternals","attributeStyleMap","autocapitalize","autofocus","blur","click","contentEditable","dataset","dir","draggable","editContext","enterKeyHint","focus","hidden","hidePopover","inert","innerText","inputMode","isContentEditable","lang","nonce","offsetHeight","offsetLeft","offsetParent","offsetTop","offsetWidth","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeinput","onbeforematch","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","outerText","popover","showPopover","spellcheck","style","tabIndex","title","togglePopover","translate","virtualKeyboardPolicy","writingSuggestions"];
const CHROME_IFACE_MEMBERS = {"HTMLAnchorElement":["attributionSrc","charset","coords","download","hash","host","hostname","href","hrefTranslate","hreflang","interestForElement","name","origin","password","pathname","ping","port","protocol","referrerPolicy","rel","relList","rev","search","shape","target","text","toString","type","username"],"HTMLBRElement":["clear"],"HTMLBodyElement":["aLink","background","bgColor","link","onafterprint","onbeforeprint","onbeforeunload","onblur","onerror","onfocus","ongamepadconnected","ongamepaddisconnected","onhashchange","onlanguagechange","onload","onmessage","onmessageerror","onoffline","ononline","onpagehide","onpageshow","onpopstate","onrejectionhandled","onresize","onscroll","onstorage","onunhandledrejection","onunload","text","vLink"],"HTMLButtonElement":["checkValidity","command","commandForElement","disabled","form","formAction","formEnctype","formMethod","formNoValidate","formTarget","interestForElement","labels","name","popoverTargetAction","popoverTargetElement","reportValidity","setCustomValidity","type","validationMessage","validity","value","willValidate"],"HTMLCanvasElement":["captureStream","getContext","height","toBlob","toDataURL","transferControlToOffscreen","width"],"HTMLDivElement":["align"],"HTMLFormElement":["acceptCharset","action","autocomplete","checkValidity","elements","encoding","enctype","length","method","name","noValidate","rel","relList","reportValidity","requestSubmit","reset","submit","target"],"HTMLHeadingElement":["align"],"HTMLHtmlElement":["version"],"HTMLIFrameElement":["adAuctionHeaders","align","allow","allowFullscreen","allowPaymentRequest","browsingTopics","contentDocument","contentWindow","credentialless","csp","featurePolicy","frameBorder","getSVGDocument","height","loading","longDesc","marginHeight","marginWidth","name","privateToken","referrerPolicy","sandbox","scrolling","sharedStorageWritable","src","srcdoc","width"],"HTMLImageElement":["align","alt","attributionSrc","border","browsingTopics","complete","crossOrigin","currentSrc","decode","decoding","fetchPriority","height","hspace","isMap","loading","longDesc","lowsrc","name","naturalHeight","naturalWidth","referrerPolicy","sharedStorageWritable","sizes","src","srcset","useMap","vspace","width","x","y"],"HTMLInputElement":["accept","align","alt","autocomplete","checkValidity","checked","defaultChecked","defaultValue","dirName","disabled","files","form","formAction","formEnctype","formMethod","formNoValidate","formTarget","height","incremental","indeterminate","labels","list","max","maxLength","min","minLength","multiple","name","pattern","placeholder","popoverTargetAction","popoverTargetElement","readOnly","reportValidity","required","select","selectionDirection","selectionEnd","selectionStart","setCustomValidity","setRangeText","setSelectionRange","showPicker","size","src","step","stepDown","stepUp","type","useMap","validationMessage","validity","value","valueAsDate","valueAsNumber","webkitEntries","webkitdirectory","width","willValidate"],"HTMLLIElement":["type","value"],"HTMLLabelElement":["control","form","htmlFor"],"HTMLLinkElement":["as","blocking","charset","crossOrigin","disabled","fetchPriority","href","hreflang","imageSizes","imageSrcset","integrity","media","referrerPolicy","rel","relList","rev","sheet","sizes","target","type"],"HTMLMetaElement":["content","httpEquiv","media","name","scheme"],"HTMLOptionElement":["defaultSelected","disabled","form","index","label","selected","text","value"],"HTMLParagraphElement":["align"],"HTMLScriptElement":["async","attributionSrc","blocking","charset","crossOrigin","defer","event","fetchPriority","htmlFor","innerText","integrity","noModule","referrerPolicy","src","text","textContent","type"],"HTMLSelectElement":["add","autocomplete","checkValidity","disabled","form","item","labels","length","multiple","name","namedItem","options","remove","reportValidity","required","selectedIndex","selectedOptions","setCustomValidity","showPicker","size","type","validationMessage","validity","value","willValidate"],"HTMLStyleElement":["blocking","disabled","media","sheet","type"],"HTMLTableElement":["align","bgColor","border","caption","cellPadding","cellSpacing","createCaption","createTBody","createTFoot","createTHead","deleteCaption","deleteRow","deleteTFoot","deleteTHead","frame","insertRow","rows","rules","summary","tBodies","tFoot","tHead","width"],"HTMLTextAreaElement":["autocomplete","checkValidity","cols","defaultValue","dirName","disabled","form","labels","maxLength","minLength","name","placeholder","readOnly","reportValidity","required","rows","select","selectionDirection","selectionEnd","selectionStart","setCustomValidity","setRangeText","setSelectionRange","textLength","type","validationMessage","validity","value","willValidate","wrap"],"HTMLTitleElement":["text"],"HTMLUListElement":["compact","type"],"HTMLVideoElement":["cancelVideoFrameCallback","disablePictureInPicture","getVideoPlaybackQuality","height","onenterpictureinpicture","onleavepictureinpicture","playsInline","poster","requestPictureInPicture","requestVideoFrameCallback","videoHeight","videoWidth","webkitDecodedFrameCount","webkitDroppedFrameCount","width"]};
  {
    const onElement = new Set(CHROME_ELEMENT);
    const onHtml = new Set(CHROME_HTMLELEMENT);
    const owners = new Map();   // имя -> [прототипы интерфейсов]
    for (const [iface, members] of Object.entries(CHROME_IFACE_MEMBERS)) {
      const proto = __ifaceProto.get(iface);
      if (!proto) continue;
      for (const m of members) {
        if (!owners.has(m)) owners.set(m, []);
        owners.get(m).push(proto);
      }
    }
    for (const name of Object.getOwnPropertyNames(Element.prototype)) {
      if (name === 'constructor' || name.lastIndexOf('__pt', 0) === 0) continue;
      if (onElement.has(name)) continue;
      const d = Object.getOwnPropertyDescriptor(Element.prototype, name);
      if (!d || !d.configurable) continue;
      const targets = onHtml.has(name) ? [__htmlProto] : (owners.get(name) || []);
      if (!targets.length) continue;   // наше собственное — оставляем как есть
      for (const proto of targets) {
        if (Object.getOwnPropertyDescriptor(proto, name)) continue;
        try { Object.defineProperty(proto, name, d); } catch (e) {}
      }
      try { delete Element.prototype[name]; } catch (e) {}
    }
    // Часть членов браузер кладёт и в SVG — они приходят из общей примеси.
    // Без них у SVG-узла не было ни объявления стиля, ни каскада: `<text
    // font-size="150">` мерился шестнадцатью пикселями, а `style.fontSize`
    // не доходил до атрибута.
    const svgRoot = globalThis.SVGElement && SVGElement.prototype;
    if (svgRoot) {
      for (const name of ['style', 'dataset', 'attributeStyleMap', 'nonce',
                          'tabIndex', 'autofocus', 'focus', 'blur']) {
        if (Object.getOwnPropertyDescriptor(svgRoot, name)) continue;
        const d = Object.getOwnPropertyDescriptor(__htmlProto, name);
        if (d) {
          try { Object.defineProperty(svgRoot, name, d); } catch (e) {}
        }
      }
    }
  }

  // Форма интерфейсов, снятая с Chrome 148: имя → категория → имена членов.
  // `Element.prototype` у нас нёс 47 имён против 151, `HTMLElement` — 16 против
  // 141, у SVGElement не было ни одного. Сборщик отпечатка идёт по цепочке
  // прототипов перечислимыми ключами, так что каждая недостающая ступень видна
  // ему сразу. Заполняем только то, чего нет: реализованное не трогаем.
  const CHROME_IFACE_SHAPE = {"AudioContext":{"N":["close","createMediaElementSource","createMediaStreamDestination","createMediaStreamSource","getOutputTimestamp","resume","suspend","setSinkId"],"x":["baseLatency","outputLatency","onerror","playbackStats","sinkId","onsinkchange"]},"BaseAudioContext":{"N":["createAnalyser","createBiquadFilter","createBuffer","createBufferSource","createChannelMerger","createChannelSplitter","createConstantSource","createConvolver","createDelay","createDynamicsCompressor","createGain","createIIRFilter","createOscillator","createPanner","createPeriodicWave","createScriptProcessor","createStereoPanner","createWaveShaper","decodeAudioData"],"x":["destination","sampleRate","currentTime","listener","state","onstatechange","audioWorklet"]},"CSSStyleDeclaration":{"#0":["length"],"N":["getPropertyPriority","getPropertyValue","item","removeProperty","setProperty"],"e":["cssText","cssFloat"],"x":["parentRule"]},"DOMTokenList":{"#2":["length"],"N":["entries","keys","values","forEach","add","contains","item","remove","replace","supports","toggle","toString"],"s:a b":["value"]},"Element":{"#0":["scrollTop","scrollLeft","clientTop","clientLeft"],"#1":["childElementCount","currentCSSZoom"],"#18":["scrollHeight","clientHeight"],"#764":["scrollWidth","clientWidth"],"N":["after","animate","append","attachShadow","before","checkVisibility","closest","computedStyleMap","getAnimations","getAttribute","getAttributeNS","getAttributeNames","getAttributeNode","getAttributeNodeNS","getBoundingClientRect","getClientRects","getElementsByClassName","getElementsByTagName","getElementsByTagNameNS","getHTML","hasAttribute","hasAttributeNS","hasAttributes","hasPointerCapture","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","matches","moveBefore","prepend","querySelector","querySelectorAll","releasePointerCapture","remove","removeAttribute","removeAttributeNS","removeAttributeNode","replaceChildren","replaceWith","requestFullscreen","requestPointerLock","scroll","scrollBy","scrollIntoView","scrollIntoViewIfNeeded","scrollTo","setAttribute","setAttributeNS","setAttributeNode","setAttributeNodeNS","setHTMLUnsafe","setPointerCapture","toggleAttribute","webkitMatchesSelector","webkitRequestFullScreen","webkitRequestFullscreen","ariaNotify","setHTML","startViewTransition"],"e":["slot","elementTiming"],"o":["classList","attributes","part","children","firstElementChild","lastElementChild","nextElementSibling","customElementRegistry"],"s:<div id=\"d\" class=\"a b\"><span>x</span></div>":["outerHTML"],"s:<span>x</span>":["innerHTML"],"s:DIV":["tagName"],"s:a b":["className"],"s:d":["id"],"s:div":["localName"],"s:http://www.w3.org/1999/xhtml":["namespaceURI"],"x":["prefix","shadowRoot","assignedSlot","onbeforecopy","onbeforecut","onbeforepaste","onsearch","onfullscreenchange","onfullscreenerror","onwebkitfullscreenchange","onwebkitfullscreenerror","role","ariaAtomic","ariaAutoComplete","ariaBusy","ariaBrailleLabel","ariaBrailleRoleDescription","ariaChecked","ariaColCount","ariaColIndex","ariaColSpan","ariaCurrent","ariaDescription","ariaDisabled","ariaExpanded","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","previousElementSibling","activeViewTransition","ariaColIndexText","ariaRowIndexText","ariaActiveDescendantElement","ariaControlsElements","ariaDescribedByElements","ariaDetailsElements","ariaErrorMessageElements","ariaFlowToElements","ariaLabelledByElements"]},"HTMLCanvasElement":{"#150":["height"],"#300":["width"],"N":["captureStream","getContext","toBlob","toDataURL","transferControlToOffscreen"]},"HTMLCollection":{"#1":["length"],"N":["item","namedItem"]},"HTMLElement":{"#-1":["tabIndex"],"#18":["offsetHeight"],"#764":["offsetWidth"],"#8":["offsetTop","offsetLeft"],"F":["hidden","inert","draggable","isContentEditable","autofocus"],"N":["attachInternals","blur","click","focus","hidePopover","showPopover","togglePopover"],"T":["translate","spellcheck"],"e":["title","lang","dir","accessKey","autocapitalize","enterKeyHint","inputMode","virtualKeyboardPolicy","nonce"],"o":["offsetParent","dataset","style","attributeStyleMap"],"s:inherit":["contentEditable"],"s:true":["writingSuggestions"],"s:x":["innerText","outerText"],"x":["editContext","popover","onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","oncopy","oncut","onpaste","onscrollsnapchange","onscrollsnapchanging","onpointerrawupdate"]},"NamedNodeMap":{"#2":["length"],"N":["getNamedItem","getNamedItemNS","item","removeNamedItem","removeNamedItemNS","setNamedItem","setNamedItemNS"]},"NodeList":{"#1":["length"],"N":["entries","keys","values","forEach","item"]},"OfflineAudioContext":{"N":["resume","startRendering","suspend"],"x":["oncomplete","length"]},"Performance":{"#0":["interactionCount"],"#1786865974979.1":["timeOrigin"],"N":["clearMarks","clearMeasures","clearResourceTimings","getEntries","getEntriesByName","getEntriesByType","mark","measure","setResourceTimingBufferSize","toJSON","now"],"o":["timing","navigation","memory","eventCounts"],"x":["onresourcetimingbufferfull"]},"SVGAnimatedLength":{"x":["baseVal","animVal"]},"SVGAnimatedRect":{"x":["baseVal","animVal"]},"SVGAnimatedString":{"x":["baseVal","animVal"]},"SVGAnimatedTransformList":{"x":["baseVal","animVal"]},"SVGCircleElement":{"o":["cx","cy","r"]},"SVGElement":{"#-1":["tabIndex"],"F":["autofocus"],"N":["blur","focus"],"e":["nonce"],"o":["className","ownerSVGElement","viewportElement","dataset","style","attributeStyleMap"],"x":["onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","oncopy","oncut","onpaste","onscrollsnapchange","onscrollsnapchanging","onpointerrawupdate"]},"SVGGeometryElement":{"N":["getPointAtLength","getTotalLength","isPointInFill","isPointInStroke"],"o":["pathLength"]},"SVGGraphicsElement":{"N":["getBBox","getCTM","getScreenCTM"],"o":["transform","nearestViewportElement","farthestViewportElement","requiredExtensions","systemLanguage"]},"SVGLength":{"N":["convertToSpecifiedUnits","newValueSpecifiedUnits"],"#0":["SVG_LENGTHTYPE_UNKNOWN"],"#1":["SVG_LENGTHTYPE_NUMBER"],"#2":["SVG_LENGTHTYPE_PERCENTAGE"],"#3":["SVG_LENGTHTYPE_EMS"],"#4":["SVG_LENGTHTYPE_EXS"],"#5":["SVG_LENGTHTYPE_PX"],"#6":["SVG_LENGTHTYPE_CM"],"#7":["SVG_LENGTHTYPE_MM"],"#8":["SVG_LENGTHTYPE_IN"],"#9":["SVG_LENGTHTYPE_PT"],"#10":["SVG_LENGTHTYPE_PC"],"x":["unitType","value","valueInSpecifiedUnits","valueAsString"]},"SVGLineElement":{"o":["x1","y1","x2","y2"]},"SVGMatrix":{"N":["flipX","flipY","inverse","multiply","rotate","rotateFromVector","scale","scaleNonUniform","skewX","skewY","translate"],"x":["a","b","c","d","e","f"]},"SVGPoint":{"N":["matrixTransform"],"x":["x","y"]},"SVGPointList":{"N":["appendItem","clear","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"SVGRect":{"x":["x","y","width","height"]},"SVGRectElement":{"o":["x","y","width","height","rx","ry"]},"SVGSVGElement":{"#0":["SVG_ZOOMANDPAN_UNKNOWN"],"#1":["currentScale","SVG_ZOOMANDPAN_DISABLE"],"#2":["zoomAndPan","SVG_ZOOMANDPAN_MAGNIFY"],"N":["animationsPaused","checkEnclosure","checkIntersection","createSVGAngle","createSVGLength","createSVGMatrix","createSVGNumber","createSVGPoint","createSVGRect","createSVGTransform","createSVGTransformFromMatrix","deselectAll","forceRedraw","getCurrentTime","getElementById","getEnclosureList","getIntersectionList","pauseAnimations","setCurrentTime","suspendRedraw","unpauseAnimations","unsuspendRedraw","unsuspendRedrawAll"],"o":["x","y","width","height","currentTranslate","viewBox","preserveAspectRatio"]},"SVGStringList":{"N":["appendItem","clear","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"SVGTransformList":{"N":["appendItem","clear","consolidate","createSVGTransformFromMatrix","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"ShadowRoot":{"F":["delegatesFocus","serializable","clonable"],"N":["elementFromPoint","elementsFromPoint","getAnimations","getHTML","getSelection","setHTMLUnsafe","setHTML"],"a":["adoptedStyleSheets"],"e":["innerHTML"],"o":["host","styleSheets","customElementRegistry"],"s:named":["slotAssignment"],"s:open":["mode"],"x":["onslotchange","activeElement","pointerLockElement","fullscreenElement","pictureInPictureElement"]},"SpeechSynthesis":{"F":["pending","speaking","paused"],"N":["cancel","getVoices","pause","resume","speak"],"x":["onvoiceschanged"]},"Storage":{"#0":["length"],"N":["clear","getItem","key","removeItem","setItem"]}};
  globalThis.__pt_fillShapes = () => {
    const native = globalThis.__pt_native || ((f) => f);
    const stub = (name, cat) => {
      if (cat === 'N') {
        const f = function () {};
        try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
        return native(f);
      }
      if (cat === 'x') return null;
      if (cat === 'u') return undefined;
      if (cat === 'T') return true;
      if (cat === 'F') return false;
      if (cat === 'e') return '';
      if (cat === 'o') return {};
      if (cat === 'a') return [];
      if (cat === 'p') { const q = Promise.resolve(); q.catch(() => {}); return q; }
      if (cat.charCodeAt(0) === 35) return Number(cat.slice(1));      // '#12' → 12
      if (cat.charCodeAt(0) === 115 && cat[1] === ':') return cat.slice(2);   // 's:auto'
      return undefined;
    };
    for (const iface of Object.keys(CHROME_IFACE_SHAPE)) {
      const C = globalThis[iface];
      const proto = C && C.prototype;
      if (!proto) continue;
      // "Уже есть" — значит есть на самом интерфейсе или ниже по цепочке DOM,
      // а не унаследовано от Object.prototype.
      const has = (name) => {
        for (let o = proto; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
          if (Object.prototype.hasOwnProperty.call(o, name)) return true;
        }
        return false;
      };
      for (const cat of Object.keys(CHROME_IFACE_SHAPE[iface])) {
        for (const name of CHROME_IFACE_SHAPE[iface][cat]) {
          if (has(name)) continue;
          try {
            Object.defineProperty(proto, name, {
              value: stub(name, cat), writable: true, enumerable: true, configurable: true,
            });
          } catch (e) {}
        }
      }
    }
  };
  __pt_fillShapes();


  // Доступ к своим кукам в стороннем кадре. Виджет Turnstile его просит, и
  // браузер после этого помечает запросы кадра отдельным заголовком; у нас
  // вызов возвращал пустоту, `.then` падал с TypeError, и виджет шёл другой
  // дорогой.
  try {
    const D = Document.prototype;
    const def = (name, fn) => {
      try {
        Object.defineProperty(D, name, {
          value: globalThis.__pt_native ? __pt_native(fn) : fn,
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    };
    def('requestStorageAccess', function requestStorageAccess(types) {
      globalThis.__ptStorageAccess = true;
      if (types && typeof types === 'object') {
        const handle = {};
        for (const k of Object.keys(types)) if (types[k]) handle[k] = true;
        return Promise.resolve(handle);
      }
      return Promise.resolve(undefined);
    });
    def('hasStorageAccess', function hasStorageAccess() { return Promise.resolve(true); });
    def('hasUnpartitionedCookieAccess', function hasUnpartitionedCookieAccess() {
      return Promise.resolve(true);
    });
    def('requestStorageAccessFor', function requestStorageAccessFor() {
      globalThis.__ptStorageAccess = true;
      return Promise.resolve(undefined);
    });
  } catch (e) {}

  globalThis.ShadowRoot = ShadowRoot;
  globalThis.Text = Text;
  globalThis.Comment = Comment;
  globalThis.Document = Document;
  globalThis.Event = Event;
  globalThis.CustomEvent = CustomEvent;
  globalThis.DocumentFragment = DocumentFragment;
  document.__ptView = globalThis;

  // <script> nodes in document order, so the loader can point `currentScript` at
  // the one it is about to run (for document.write positioning).
  let scriptNodes = [];

  // Called by the loader with the Rust-parsed <html> tree.
  // Документ дочернего окна, построенный на месте — без сети и без движка.
  // Пустой iframe в браузере получает `<html><head></head><body></body></html>`,
  // а `srcdoc` — разобранную разметку; и в обоих случаях скрипты внутри
  // исполняются в этом окне. У нас документ реалма был пуст, поэтому и
  // `contentDocument.body` был null, и класть туда было некуда.
  // `DOMParser` и `XMLSerializer` — обычные места в сборе отпечатка, и у нас
  // это были пустые классы из таблицы имён: вызов бросал `TypeError`. Разбор
  // идёт тем же разбором, что и присваивание `innerHTML`, а запись — тем же
  // сериализатором, что и `outerHTML`, только с пространством имён на корне,
  // как это делает браузер.
  const VOID_XML = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
    'link', 'meta', 'param', 'source', 'track', 'wbr']);
  globalThis.__pt_lateDom = {
    parseDocument(markup, type) {
      const kind = String(type || 'text/html').toLowerCase();
      const doc = new Document();
      Object.defineProperty(doc, '__ptContentType', { value: kind, writable: true, configurable: true });
      const isHtml = kind === 'text/html';
      if (!isHtml) Object.defineProperty(doc, '__ptXml', { value: true, writable: true, configurable: true });
      const nodes = isHtml ? parseFragment(String(markup == null ? '' : markup)) : (() => {
        const r = this.parseXml(doc, String(markup == null ? '' : markup));
        let root = r.nodes.find((n) => n.nodeType === ELEMENT_NODE);
        if (r.error) {
          // Ошибка разбора у Chrome (libxml2): <parsererror> первым ребёнком
          // корня, а без корня — html/body/parsererror.
          const pe = this.parseErrorNode(doc, r.error);
          if (root) __ptInsert.call(root, pe, root.firstChild);
          else {
            root = doc.createElement('html'); __ptSetAttr.call(root, 'xmlns', 'http://www.w3.org/1999/xhtml');
            const body = doc.createElement('body'); __ptAdd.call(root, body); __ptAdd.call(body, pe);
            return [root];
          }
        }
        return r.nodes;
      })();
      let root = nodes.find((n) => n.nodeType === ELEMENT_NODE && n.localName === 'html');
      if (!root && isHtml) {
        root = doc.createElement('html');
        const head = doc.createElement('head');
        const body = doc.createElement('body');
        __ptAdd.call(root, head);
        __ptAdd.call(root, body);
        for (const n of nodes) __ptAdd.call(body, n);
      } else if (!root) {
        root = nodes.find((n) => n.nodeType === ELEMENT_NODE) || doc.createElement('html');
      } else if (isHtml) {
        if (!__tags(root, 'head')[0]) __ptInsert.call(root, doc.createElement('head'), root.firstChild);
        if (!__tags(root, 'body')[0]) __ptAdd.call(root, doc.createElement('body'));
      }
      __ptAdd.call(doc, root);
      doc.__ptDocEl = root;
      __walkTree(doc, (n) => { n.__ptDoc = doc; });
      // Документ из строки готов сразу, окна у него нет (`location` — своё
      // свойство, null), а класс — HTMLDocument или XMLDocument, как у Chrome.
      doc.__ptReady = 'complete';
      try {
        const g = function () { return null; };
        try { Object.defineProperty(g, 'name', { value: 'get location', configurable: true }); } catch (e) {}
        Object.defineProperty(doc, 'location', { get: globalThis.__pt_native ? __pt_native(g) : g, set: undefined, enumerable: true, configurable: false });
      } catch (e) {}
      try {
        if (isHtml) {
          const hp = globalThis.document && Object.getPrototypeOf(globalThis.document);
          if (hp && hp !== Document.prototype && hp.constructor && hp.constructor.name === 'HTMLDocument') Object.setPrototypeOf(doc, hp);
          else if (typeof globalThis.HTMLDocument === 'function' && globalThis.HTMLDocument.prototype && Object.getPrototypeOf(globalThis.HTMLDocument.prototype) === Document.prototype) Object.setPrototypeOf(doc, globalThis.HTMLDocument.prototype);
        } else if (typeof globalThis.XMLDocument === 'function' && globalThis.XMLDocument.prototype && Object.getPrototypeOf(globalThis.XMLDocument.prototype) === Document.prototype) {
          Object.setPrototypeOf(doc, globalThis.XMLDocument.prototype);
        }
      } catch (e) {}
      return doc;
    },
    // ---- XML: разбор по правилам XML с ошибками в словах libxml2 — так их
    // показывает Chrome (`error on line L at column C: …`).
    parseXml(doc, src) {
      const out = { nodes: [], error: null };
      let i = 0; const n = src.length; let line = 1, ls = 0;
      const stack = [];
      const push = (node) => { const top = stack[stack.length - 1]; if (top) __ptAdd.call(top, node); else out.nodes.push(node); };
      const col = (at) => at - ls + 1;
      const fail = (msg, at) => { if (!out.error) out.error = { msg, line, col: col(at === undefined ? i : at) }; };
      const text = (t) => doc.createTextNode(t);
      const decode = (s) => s.replace(/&(#[xX][0-9a-fA-F]+|#[0-9]+|[A-Za-z_][\w.\-]*);/g, (m, e) => {
        if (e[0] === '#') { const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '\ufffd'; }
        const p = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e];
        if (p === undefined) { fail("Entity '" + e + "' not defined"); return ''; }
        return p;
      });
      let rootSeen = false;
      const advance = (from, to) => { for (let k = from; k < to; k++) if (src.charCodeAt(k) === 10) { line++; ls = k + 1; } };
      while (i < n && !out.error) {
        if (src[i] === '<') {
          if (src.startsWith('<?', i)) { const e = src.indexOf('?>', i + 2); if (e < 0) { fail("Parsing XML declaration: '?>' expected"); break; } advance(i, e + 2); i = e + 2; continue; }
          if (src.startsWith('<!--', i)) { const e = src.indexOf('-->', i + 4); if (e < 0) { fail('Comment not terminated'); break; } push(doc.createComment(src.slice(i + 4, e))); advance(i, e + 3); i = e + 3; continue; }
          if (src.startsWith('<![CDATA[', i)) { const e = src.indexOf(']]>', i + 9); if (e < 0) { fail('CData section not finished'); break; } if (!stack.length) { fail('Extra content at the end of the document'); break; } push(text(src.slice(i + 9, e))); advance(i, e + 3); i = e + 3; continue; }
          if (src.startsWith('<!DOCTYPE', i)) { const e = src.indexOf('>', i); if (e < 0) { fail('DOCTYPE improperly terminated'); break; } advance(i, e + 1); i = e + 1; continue; }
          if (src[i + 1] === '/') {
            const m = /^<\/([^\s>]+)\s*>/.exec(src.slice(i));
            if (!m) { fail("expected '>'"); break; }
            const top = stack[stack.length - 1];
            if (!top) { fail('Extra content at the end of the document'); break; }
            if (top.__ptLocal !== m[1]) { fail('Opening and ending tag mismatch: ' + top.__ptLocal + ' line ' + top.__ptLine + ' and ' + m[1], i + m[0].length + 1); break; }
            stack.pop(); i += m[0].length; continue;
          }
          const m = /^<([A-Za-z_:][\w:.\-]*)/.exec(src.slice(i));
          if (!m) { fail('StartTag: invalid element name', i + 1); break; }
          if (!stack.length && rootSeen) { fail('Extra content at the end of the document'); break; }
          let el = doc.createElement(m[1]); el.__ptLine = line;
          let j = i + m[0].length;
          for (;;) {
            j += /^\s*/.exec(src.slice(j))[0].length;
            if (src[j] === '>') { j++; break; }
            if (src.startsWith('/>', j)) { j += 2; push(el); if (!stack.length) rootSeen = true; el = null; break; }
            const am = /^([A-Za-z_:][\w:.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/.exec(src.slice(j));
            if (!am) {
              const nm = /^([A-Za-z_:][\w:.\-]*)/.exec(src.slice(j));
              if (nm) fail('Specification mandates value for attribute ' + nm[1], j + nm[0].length); else fail('error parsing attribute name', j);
              break;
            }
            const val = am[2] !== undefined ? am[2] : am[3];
            if (val.indexOf('<') >= 0) { fail("Unescaped '<' not allowed in attributes values", j); break; }
            if (__ptHasA(el, am[1])) { fail('Attribute ' + am[1] + ' redefined', j); break; }
            __ptSetAttr.call(el, am[1], decode(val)); j += am[0].length;
          }
          if (out.error) break;
          if (el) { push(el); if (!stack.length) rootSeen = true; stack.push(el); }
          advance(i, j); i = j; continue;
        }
        const next = src.indexOf('<', i); const stop = next < 0 ? n : next;
        const chunk = src.slice(i, stop);
        if (!stack.length) {
          if (chunk.trim()) { fail(rootSeen ? 'Extra content at the end of the document' : "Start tag expected, '<' not found", i + (chunk.length - chunk.replace(/^\s+/, '').length)); break; }
        } else push(text(decode(chunk)));
        advance(i, stop); i = stop;
      }
      if (!out.error && stack.length) { const top = stack[stack.length - 1]; fail('Premature end of data in tag ' + top.__ptLocal + ' line ' + top.__ptLine, n); }
      if (!out.error && !rootSeen) fail(src.trim() ? "Start tag expected, '<' not found" : 'Document is empty', 0);
      return out;
    },
    parseErrorNode(doc, err) {
      const mk = (name, attrs, txt) => { const e = doc.createElement(name); for (const k of Object.keys(attrs)) __ptSetAttr.call(e, k, attrs[k]); if (txt != null) __ptAdd.call(e, doc.createTextNode(txt)); return e; };
      const pe = mk('parsererror', { xmlns: 'http://www.w3.org/1999/xhtml', style: 'display: block; white-space: pre; border: 2px solid #c77; padding: 0 1em 0 1em; margin: 1em; background-color: #fdd; color: black' }, null);
      __ptAdd.call(pe, mk('h3', {}, 'This page contains the following errors:'));
      __ptAdd.call(pe, mk('div', { style: 'font-family:monospace;font-size:12px' }, 'error on line ' + err.line + ' at column ' + err.col + ': ' + err.msg + '\n'));
      __ptAdd.call(pe, mk('h3', {}, 'Below is a rendering of the page up to the first error.'));
      return pe;
    },
    serializeXml(node) {
      // Документ целиком — это его корневой элемент с xmlns.
      if (node && node.nodeType === 9 && node.documentElement) node = node.documentElement;
      const one = (n, root) => {
        if (n.nodeType === TEXT_NODE) return esc(String(n.data), false);
        if (n.nodeType === COMMENT_NODE) return '<!--' + n.data + '-->';
        if (n.nodeType !== ELEMENT_NODE) {
          // Дети обрывка (в том числе теневого корня) — каждый сам себе корень:
          // xmlns у каждого элемента верхнего уровня, как у Chrome.
          return (n.__ptKids || []).map((c) => one(c, root)).join('');
        }
        const tag = n.localName;
        let attrs = '';
        if (root && !(n.ownerDocument && n.ownerDocument.__ptXml)) attrs += ' xmlns="http://www.w3.org/1999/xhtml"';
        for (const { name, value } of n.attributes) attrs += ' ' + name + '="' + esc(String(value), true) + '"';
        const kids = (n.__ptKids || []).map((c) => one(c, false)).join('');
        if (!kids && VOID_XML.has(tag)) return '<' + tag + attrs + ' />';
        return '<' + tag + attrs + '>' + kids + '</' + tag + '>';
      };
      // Обрывок и теневой корень: их дети верхнего уровня — корни (xmlns).
      return one(node, node && (node.nodeType === ELEMENT_NODE || node.nodeType === DOCUMENT_FRAGMENT_NODE));
    },
  };

  // `window.length` и `window.frames[i]` — счёт живых кадров. У нас там
  // стоял ноль при любом числе рамок, а это первое, что спрашивают о
  // странице: у браузера длина равна числу кадров, а по номеру лежит их
  // окно. Пересчитывается по дереву, чтобы не разъезжаться со вставками.
  {
    const frameEls = () => {
      const out = [];
      const doc = globalThis.document;
      if (!doc || !doc.documentElement) return out;
      // Только светлое дерево: кадры внутри теневых корней в `window.length`
      // у Chrome не считаются.
      const walk = (n) => {
        if (n.nodeType === ELEMENT_NODE && (n.__ptLocal === 'iframe' || n.__ptLocal === 'frame')) out.push(n);
        for (const k of (n.__ptKids || [])) walk(k);
      };
      walk(doc.documentElement);
      return out;
    };
    const windowOf = (el) => {
      try { return el.contentWindow || null; } catch (e) { return null; }
    };
    try {
      Object.defineProperty(globalThis, 'length', {
        get: () => frameEls().length,
        enumerable: true, configurable: true,
      });
    } catch (e) {}
    // Номерные свойства окна: браузер держит ровно столько, сколько кадров,
    // и держит их значениями — не переписываемыми, перечислимыми. У нас
    // стояло шестнадцать акцессоров всегда, и страница без единого кадра
    // показывала шестнадцать номеров, которых у браузера нет.
    globalThis.__pt_frameAt = (i) => {
      const els = frameEls();
      return i >= 0 && i < els.length ? windowOf(els[i]) : undefined;
    };
    let __slots = 0;
    const __syncSlots = () => {
      const n = frameEls().length;
      for (let i = 0; i < n; i++) {
        try {
          Object.defineProperty(globalThis, String(i), {
            value: globalThis.__pt_frameAt(i),
            writable: false, enumerable: true, configurable: true,
          });
        } catch (e) {}
      }
      for (let i = n; i < __slots; i++) { try { delete globalThis[String(i)]; } catch (e) {} }
      __slots = n;
    };
    globalThis.__pt_syncFrameSlots = __syncSlots;
    __syncSlots();
  }


  // ---- Content Security Policy ---------------------------------------------
  // Политика документа — из заголовка ответа (движок зовёт `__pt_applyCsp`) и
  // из `<meta http-equiv="content-security-policy">`. Считается только
  // `script-src` (с откатом к `default-src`): без 'unsafe-eval' строка в
  // eval/Function/setTimeout бросает EvalError с текстом Chrome, WebAssembly
  // без 'wasm-unsafe-eval' — CompileError, воркер с blob:/data: — SecurityError,
  // инлайн-скрипт без nonce не исполняется, и документ получает
  // securitypolicyviolation.
  const __csp = { policies: [] };
  const __cspParse = (text) => {
    const out = {};
    for (const part of String(text).split(';')) {
      const toks = part.trim().split(/\s+/).filter(Boolean);
      if (!toks.length) continue;
      const name = toks[0].toLowerCase();
      if (!(name in out)) out[name] = toks.slice(1);
    }
    return out;
  };
  const __cspScriptDirective = (p) => (p.dirs['script-src'] ? ['script-src', p.dirs['script-src']] : (p.dirs['default-src'] ? ['default-src', p.dirs['default-src']] : null));
  const __cspHas = (list, kw) => list.some((t) => t.toLowerCase() === kw);
  const __cspDirectiveText = (name, list) => name + (list.length ? ' ' + list.join(' ') : '');
  // Строка и столбец места вызова — из стека, первый кадр страницы.
  const __cspSite = () => {
    try {
      const st = String(new Error().stack || '').split('\n');
      for (const line of st.slice(1)) {
        const m = /(https?:[^\s()]+|about:[^\s()]+):(\d+):(\d+)\)?\s*$/.exec(line);
        if (m && !/<anonymous>/.test(line)) return { file: m[1], line: +m[2], column: +m[3] };
      }
    } catch (e) {}
    return { file: '', line: 0, column: 0 };
  };
  // SecurityPolicyViolationEvent с полями из init: заглушка интерфейса их не
  // отражала (blockedURI отвечал undefined).
  const __spveState = new WeakMap();
  const __SPVE_FIELDS = [['documentURI', ''], ['referrer', ''], ['blockedURI', ''], ['effectiveDirective', ''], ['violatedDirective', ''], ['originalPolicy', ''], ['sourceFile', ''], ['sample', ''], ['disposition', 'enforce'], ['statusCode', 0], ['lineNumber', 0], ['columnNumber', 0]];
  const __spveEnsure = () => {
    const Ev = globalThis.Event;
    if (!Ev) return null;
    let E = globalThis.SecurityPolicyViolationEvent;
    let ok = false;
    try { const t = new E('x', { blockedURI: 'y' }); ok = t.blockedURI === 'y'; } catch (e) {}
    if (ok) return E;
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const oldProto = E && E.prototype && typeof E.prototype === 'object' ? E.prototype : null;
    const C = function SecurityPolicyViolationEvent(type, init) {
      if (!new.target) throw new TypeError("Failed to construct 'SecurityPolicyViolationEvent': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
      if (arguments.length < 1) throw new TypeError("Failed to construct 'SecurityPolicyViolationEvent': 1 argument required, but only 0 present.");
      const ev = Reflect.construct(Ev, [type, init], new.target);
      const st = {};
      for (const [k, dflt] of __SPVE_FIELDS) { const v = init && init[k]; st[k] = v === undefined ? dflt : (typeof dflt === 'number' ? (Number(v) | 0) : String(v)); }
      __spveState.set(ev, st);
      return ev;
    };
    C.prototype = oldProto || Object.create(Ev.prototype);
    try { Object.setPrototypeOf(C.prototype, Ev.prototype); } catch (e) {}
    try { Object.setPrototypeOf(C, Ev); } catch (e) {}
    try { Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true }); } catch (e) {}
    for (const [k] of __SPVE_FIELDS) {
      try { Object.defineProperty(C.prototype, k, { get: nat(function () { const st = __spveState.get(this); if (!st) throw new TypeError('Illegal invocation'); return st[k]; }, 'get ' + k), enumerable: true, configurable: true }); } catch (e) {}
    }
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: 'SecurityPolicyViolationEvent', configurable: true }); } catch (e) {}
    try { Object.defineProperty(C, 'length', { value: 1, configurable: true }); } catch (e) {}
    try { Object.defineProperty(globalThis, 'SecurityPolicyViolationEvent', { value: nat(C, 'SecurityPolicyViolationEvent'), writable: true, enumerable: false, configurable: true }); } catch (e) {}
    return C;
  };
  // Адрес в отчёте о нарушении: у http(s) — без учётных данных и якоря, у
  // остальных схем (about:srcdoc, blob:) — одна схема, как у браузера.
  const __cspStripURL = (u) => {
    u = String(u || ''); if (!u) return '';
    if (/^https?:|^wss?:/.test(u)) { try { const x = new URL(u); x.username = ''; x.password = ''; x.hash = ''; return x.href; } catch (e) { return u; } }
    const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(u); return m ? m[1] : u;
  };
  const __cspViolation = (name, list, blockedURI, sample, extra) => {
    try {
      const E = __spveEnsure();
      const site = extra && extra.noSite ? { file: '', line: 0, column: 0 } : __cspSite();
      const docURL = String((globalThis.location && location.href) || 'about:blank');
      const init = Object.assign({
        documentURI: __cspStripURL(docURL), referrer: String(document.referrer || ''), blockedURI, violatedDirective: name, effectiveDirective: name,
        originalPolicy: __csp.policies.map((p) => p.raw).join(', '), disposition: 'enforce', sourceFile: __cspStripURL(site.file), sample: String(sample || '').slice(0, 40), statusCode: /^https?:/.test(docURL) ? 200 : 0, lineNumber: site.line, columnNumber: site.column,
      }, extra || {});
      delete init.noSite;
      const ev = typeof E === 'function' ? new E('securitypolicyviolation', Object.assign({ bubbles: true, composed: true }, init)) : new Event('securitypolicyviolation', { bubbles: true });
      setTimeout(() => { try { document.dispatchEvent(ev); } catch (e) {} }, 0);
    } catch (e) {}
  };
  const __cspEvalMessage = () => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d || __cspHas(d[1], "'unsafe-eval'")) continue;
      // Текст Chrome 151 — с его же висячей кавычкой в конце.
      return { name: d[0], list: d[1], msg: "Evaluating a string as JavaScript violates the following Content Security Policy directive because 'unsafe-eval' is not an allowed source of script: " + __cspDirectiveText(d[0], d[1]) + "\".\n" };
    }
    return null;
  };
  const __cspWasmMessage = () => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d || __cspHas(d[1], "'unsafe-eval'") || __cspHas(d[1], "'wasm-unsafe-eval'")) continue;
      return { name: d[0], list: d[1], msg: "Compiling or instantiating WebAssembly module violates the following Content Security policy directive because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: \"" + __cspDirectiveText(d[0], d[1]) + "\"." };
    }
    return null;
  };
  // Разрешён ли адрес скрипта по списку источников (без учёта nonce/hash).
  const __cspAllowsUrl = (list, url, nonce) => {
    const u = String(url || '');
    if (nonce && list.some((t) => t.toLowerCase() === "'nonce-" + nonce.toLowerCase() + "'" || t === "'nonce-" + nonce + "'")) return true;
    if (__cspHas(list, "'strict-dynamic'")) return false;
    const scheme = (u.match(/^([a-z][a-z0-9+.-]*):/i) || [])[1];
    const self_ = (globalThis.location && location.origin) || '';
    for (const t of list) {
      const low = t.toLowerCase();
      if (low === '*') { if (scheme && !/^(blob|data|filesystem)$/i.test(scheme)) return true; continue; }
      if (low === "'self'") { if (self_ && u.indexOf(self_ + '/') === 0) return true; continue; }
      if (/^[a-z][a-z0-9+.-]*:$/i.test(low)) { if (scheme && low === scheme.toLowerCase() + ':') return true; continue; }
      if (low.charAt(0) === "'") continue;
      // host-source: сравнить схему+хост(+порт), звёздочка в начале хоста.
      try {
        const hs = low.indexOf('://') > 0 ? low : ((globalThis.location && location.protocol) || 'https:') + '//' + low;
        const want = new URL(hs.replace(/\*\./g, 'wild.')), got = new URL(u, (globalThis.location && location.href) || undefined);
        if (want.protocol !== got.protocol) continue;
        const wh = want.hostname, gh = got.hostname;
        const okHost = /^\*\./.test(low.replace(/^[a-z]+:\/\//, '')) ? (gh === wh.replace(/^wild\./, '') || gh.endsWith('.' + wh.replace(/^wild\./, ''))) : gh === wh;
        if (!okHost) continue;
        if (want.port && want.port !== got.port) continue;
        if (want.pathname && want.pathname !== '/' && got.pathname.indexOf(want.pathname) !== 0) continue;
        return true;
      } catch (e) {}
    }
    return false;
  };
  // Инлайн-скрипт: nonce/hash/'unsafe-inline' (последний отменяется nonce/hash).
  const __cspAllowsInline = (el) => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d) continue;
      const list = d[1];
      const hasNonceOrHash = list.some((t) => /^'(nonce-|sha(256|384|512)-)/i.test(t));
      const nonce = el && (__ptGetA(el, 'nonce') || el.__ptNonce || '');
      if (nonce && list.some((t) => t === "'nonce-" + nonce + "'")) continue;
      if (!hasNonceOrHash && __cspHas(list, "'unsafe-inline'")) continue;
      return { name: d[0], list };
    }
    return null;
  };
  const __cspReport = (what) => { try { (globalThis.__pt_parentConsole || console).error(what); } catch (e) {} };
  globalThis.__pt_cspBlocksInline = (el) => {
    const v = __cspAllowsInline(el);
    if (!v) return false;
    const text = __cspDirectiveText(v.name, v.list);
    __cspReport("Refused to execute inline script because it violates the following Content Security Policy directive: \"" + text + "\". Either the 'unsafe-inline' keyword, a hash ('sha256-…'), or a nonce ('nonce-...') is required to enable inline execution.\n");
    __cspViolation(v.name, v.list, 'inline', '', { violatedDirective: 'script-src-elem', effectiveDirective: 'script-src-elem', sourceFile: __cspStripURL(String((globalThis.location && location.href) || '')), lineNumber: (typeof __pt_markupLine === 'function' ? __pt_markupLine(String(el.textContent || '')) : 0) || 0, columnNumber: 0, noSite: true });
    return true;
  };
  // Обработчик в атрибуте (`onclick="…"`): script-src-attr.
  globalThis.__pt_cspBlocksHandler = (el, name, code) => {
    const v = __cspAllowsInline(null);
    if (!v) return false;
    const text = __cspDirectiveText(v.name, v.list);
    __cspReport("Refused to execute inline event handler because it violates the following Content Security Policy directive: \"" + text + "\". Either the 'unsafe-inline' keyword, a hash ('sha256-…'), or a nonce ('nonce-...') is required to enable inline execution.\n");
    __cspViolation(v.name, v.list, 'inline', '', { violatedDirective: 'script-src-attr', effectiveDirective: 'script-src-attr', sourceFile: String((globalThis.location && location.href) || '') });
    return true;
  };
  globalThis.__pt_cspBlocksScriptUrl = (el, url) => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d) continue;
      const nonce = el && (__ptGetA(el, 'nonce') || el.__ptNonce || '');
      if (__cspAllowsUrl(d[1], url, nonce)) continue;
      const text = __cspDirectiveText(d[0], d[1]);
      __cspReport("Refused to load the script '" + url + "' because it violates the following Content Security Policy directive: \"" + text + "\". Note that 'script-src-elem' was not explicitly set, so 'script-src' is used as a fallback.\n");
      __cspViolation(d[0], d[1], String(url), '', { violatedDirective: 'script-src-elem', effectiveDirective: 'script-src-elem', sourceFile: '', lineNumber: 0, columnNumber: 0, noSite: true });
      return true;
    }
    return false;
  };
  // Нарушение от прямого eval/Function: зовётся из подменённого источника
  // (см. modify_codegen в pool) перед броском EvalError.
  try { Object.defineProperty(globalThis, '__pt_cspEvalViolation', { value: () => { const e = __cspEvalMessage(); if (e) __cspViolation(e.name, e.list, 'eval'); }, writable: true, enumerable: false, configurable: true }); } catch (e) {}
  const __cspWrapEval = () => {
    const ev = __cspEvalMessage();
    try { Object.defineProperty(globalThis, '__pt_cspEval', { value: ev ? ev.msg : '', writable: true, enumerable: false, configurable: true }); } catch (e) {}
    try { if (typeof globalThis.__pt_setCodegen === 'function') __pt_setCodegen(!ev); } catch (e) {}
    if (!ev || __csp.wrapped) return;
    __csp.wrapped = true;
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    // Конструкторы функций из строки: Function и его async/generator-родня,
    // в том числе через `.constructor` у прототипов.
    try {
      const evalErr = () => { const e = __cspEvalMessage(); __cspViolation(e.name, e.list, 'eval'); return new EvalError(e.msg); };
      const seen = [];
      const ctors = [globalThis.Function];
      for (const mk of [() => Object.getPrototypeOf(async function () {}).constructor, () => Object.getPrototypeOf(function* () {}).constructor, () => Object.getPrototypeOf(async function* () {}).constructor]) { try { ctors.push(mk()); } catch (e) {} }
      for (const real of ctors) {
        if (typeof real !== 'function' || seen.includes(real)) continue;
        seen.push(real);
        const w = function (...a) { throw evalErr(); };
        w.prototype = real.prototype;
        try { Object.defineProperty(w, 'name', { value: real.name, configurable: true }); Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
        const masked = nat(w, real.name);
        try { Object.defineProperty(real.prototype, 'constructor', { value: masked, writable: true, enumerable: false, configurable: true }); } catch (e) {}
        if (real === globalThis.Function) { try { Object.defineProperty(globalThis, 'Function', { value: masked, writable: true, enumerable: false, configurable: true }); } catch (e) {} }
      }
    } catch (e) {}
    // Таймеры со строкой: у Chrome вызов отвечает номером, строка не
    // исполняется, документ получает нарушение с blockedURI 'eval'.
    for (const name of ['setTimeout', 'setInterval']) {
      try {
        const real = globalThis[name]; if (typeof real !== 'function') continue;
        const w = ({ [name](handler, ...rest) { if (typeof handler !== 'function') { const e = __cspEvalMessage(); if (e) { __cspViolation(e.name, e.list, 'eval'); return 0; } } return real.call(this, handler, ...rest); } })[name];
        try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, name, { value: nat(w, name), writable: true, enumerable: true, configurable: true });
      } catch (e) {}
    }
    // WebAssembly: компиляция и инстанцирование.
    try {
      const W = globalThis.WebAssembly;
      if (W) {
        const CE = W.CompileError || Error;
        const wasmErr = (k) => { const m = __cspWasmMessage(); if (!m) return null; __cspViolation(m.name, m.list, 'wasm-eval'); return new CE('WebAssembly.' + k + '(): ' + m.msg); };
        for (const k of ['compile', 'instantiate', 'compileStreaming', 'instantiateStreaming']) {
          const real = W[k]; if (typeof real !== 'function') continue;
          const w = ({ [k](...a) { const e = wasmErr(k); if (e) return Promise.reject(e); return real.apply(this, a); } })[k];
          try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
          Object.defineProperty(W, k, { value: nat(w, k), writable: true, enumerable: false, configurable: true });
        }
        for (const k of ['Module', 'Instance']) {
          const real = W[k]; if (typeof real !== 'function') continue;
          const w = function (...a) { if (!new.target) throw new TypeError("WebAssembly." + k + " must be invoked with 'new'"); const e = wasmErr(k); if (e) throw e; return Reflect.construct(real, a, new.target); };
          w.prototype = real.prototype;
          for (const sk of Object.getOwnPropertyNames(real)) { if (['length', 'name', 'prototype'].includes(sk)) continue; try { Object.defineProperty(w, sk, Object.getOwnPropertyDescriptor(real, sk)); } catch (e) {} }
          try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
          Object.defineProperty(W, k, { value: nat(w, k), writable: true, enumerable: false, configurable: true });
        }
      }
    } catch (e) {}
    // Воркеры: адрес скрипта против script-src (blob:/data: без явной схемы — нет).
    for (const name of ['Worker', 'SharedWorker']) {
      try {
        const real = globalThis[name]; if (typeof real !== 'function') continue;
        const w = function (url, opts) {
          if (!new.target) throw new TypeError("Failed to construct '" + name + "': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
          const u = String(url);
          for (const p of __csp.policies) {
            const d = __cspScriptDirective(p);
            if (!d) continue;
            if (__cspAllowsUrl(d[1], u, '')) continue;
            const text = __cspDirectiveText(d[0], d[1]);
            __cspReport("Refused to create a worker from '" + u + "' because it violates the following Content Security Policy directive: \"" + text + "\". Note that 'worker-src' was not explicitly set, so 'script-src' is used as a fallback.\n");
            const scheme = (u.match(/^([a-z][a-z0-9+.-]*):/i) || [])[1];
            __cspViolation(d[0], d[1], /^(blob|data|filesystem)$/i.test(scheme || '') ? scheme.toLowerCase() : u, '', { violatedDirective: 'worker-src', effectiveDirective: 'worker-src' });
            // У браузера конструктор отвечает объектом, а скрипт не грузится:
            // воркер получает событие error.
            const dead = Reflect.construct(real, ['data:text/javascript,', opts], new.target);
            try { dead.terminate(); } catch (e) {}
            setTimeout(() => { try { dead.dispatchEvent(new ErrorEvent('error', { message: 'Failed to load worker script' })); } catch (e) {} }, 0);
            return dead;
          }
          return Reflect.construct(real, [url, opts], new.target);
        };
        w.prototype = real.prototype;
        try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, name, { value: nat(w, name), writable: true, enumerable: false, configurable: true });
      } catch (e) {}
    }
  };
  globalThis.__pt_applyCsp = (text, source) => {
    const raw = String(text == null ? '' : text).trim();
    if (!raw) return;
    for (const one of raw.split(',')) {
      const t = one.trim();
      if (!t) continue;
      __csp.policies.push({ raw: t, dirs: __cspParse(t), source: source || 'meta' });
    }
    __cspWrapEval();
  };
  globalThis.__pt_cspActive = () => __csp.policies.length > 0;
  // Мета-политика документа: применяется, как только разметка разобрана.
  globalThis.__pt_cspFromMeta = (root) => {
    try {
      const metas = [];
      __walkTree(root, (n) => { if (n && n.nodeType === ELEMENT_NODE && String(n.__ptLocal || '').toLowerCase() === 'meta' && String(__ptGetA(n, 'http-equiv') || '').toLowerCase() === 'content-security-policy') metas.push(n); });
      for (const m of metas) { const c = __ptGetA(m, 'content'); if (c) __pt_applyCsp(c, 'meta'); }
    } catch (e) {}
  };
  // Строка разметки, с которой начинается текст: для номеров строк стека и
  // нарушений CSP (браузер считает их от начала документа).
  globalThis.__pt_markupLine = (text) => {
    try {
      const m = document.__ptMarkup; if (typeof m !== 'string' || !text) return 0;
      const i = m.indexOf(text); if (i < 0) return 0;
      let n = 1; for (let k = 0; k < i; k++) if (m.charCodeAt(k) === 10) n++;
      return n;
    } catch (e) { return 0; }
  };
  globalThis.__pt_writeDocument = (html) => {
    try { Object.defineProperty(document, '__ptMarkup', { value: String(html == null ? '' : html), configurable: true, writable: true }); } catch (e) {}
    const nodes = parseFragment(String(html == null ? '' : html));
    let root = nodes.find((n) => n.nodeType === 1 && n.tagName === 'HTML');
    if (!root) {
      root = document.createElement('html');
      for (const n of nodes) root.appendChild(n);
    }
    if (!__tags(root, 'head')[0]) root.insertBefore(document.createElement('head'), root.firstChild);
    let body = __tags(root, 'body')[0];
    if (!body) {
      body = document.createElement('body');
      // Всё, что разметка положила мимо head, — содержимое тела.
      const head = __tags(root, 'head')[0];
      for (const n of root.childNodes.slice ? root.childNodes.slice() : Array.from(root.childNodes)) {
        if (n !== head) { root.removeChild(n); body.appendChild(n); }
      }
      root.appendChild(body);
    }
    document.__ptKids = [];
    document.__ptDocEl = null;
    // Политика — до подключения дерева: скрипты исполняются при подключении.
    __pt_cspFromMeta(root);
    document.appendChild(root);
    document.__ptDocEl = root;
    document.__ptReady = 'complete';
    // Скрипты разметки исполняются здесь и сейчас, в этом окне.
    for (const el of __tags(root, 'script')) {
      try { el.__ptRunScript(); } catch (e) {}
    }
    return document;
  };

  globalThis.__pt_installDocument = (tree, dt, markup) => {
    if (typeof markup === 'string') { try { Object.defineProperty(document, '__ptMarkup', { value: markup, configurable: true, writable: true }); } catch (e) {} }
    document.__ptKids = [];
    document.__ptDocEl = null;
    document.__ptCurScript = null;
    // `<!DOCTYPE html>` — это узел документа, первый его ребёнок, а не флаг.
    document.__ptDoctype = null;
    if (dt) {
      // Узел обязан называть себя: `Object.prototype.toString.call(doctype)` —
      // `[object DocumentType]`, как у всякого интерфейса.
      try {
        if (globalThis.DocumentType && !Object.getOwnPropertyDescriptor(DocumentType.prototype, Symbol.toStringTag)) {
          Object.defineProperty(DocumentType.prototype, Symbol.toStringTag, { value: 'DocumentType', configurable: true });
        }
      } catch (e) {}
      const node = Object.create((globalThis.DocumentType && DocumentType.prototype) || Object.prototype);
      Object.defineProperty(node, '__ptE', { value: {}, enumerable: false, writable: true });
      for (const [k, v] of [['name', String(dt.name || 'html')], ['publicId', String(dt.publicId || '')],
                            ['systemId', String(dt.systemId || '')], ['nodeName', String(dt.name || 'html')],
                            ['nodeType', 10], ['nodeValue', null], ['textContent', null],
                            ['ownerDocument', document], ['parentNode', document], ['childNodes', []]]) {
        Object.defineProperty(node, k, { get: () => v, configurable: true });
      }
      document.__ptDoctype = node;
      document.__ptKids.push(node);
    }
    if (tree && tree.k === 'e') {
      const html = buildNode(document, tree);
      __pt_cspFromMeta(html);
      document.appendChild(html);
      document.__ptDocEl = html;
    }
    scriptNodes = __docTags(document, 'script');
    // Пока идут собственные скрипты документа, браузер отвечает 'loading', и
    // код это читает: «если не loading — запускайся сразу, иначе жди
    // DOMContentLoaded». Мы отвечали 'interactive' с самого начала, то есть
    // всегда первую ветку.
    document.__ptReady = 'loading';
  };

  // The loader brackets each page script with these so `document.currentScript`
  // (and therefore document.write's insertion point) is correct while it runs.
  // The index matches the loader's document-order script list.
  // Скрипт документа — задача; дольше 50 мс — запись long-animation-frame.
  let __ptScriptT0 = 0;
  globalThis.__pt_beginScript = (i) => { document.__ptCurScript = scriptNodes[i] || null; try { __ptScriptT0 = performance.now(); } catch (e) {} };
  // Скрипт документа под CSP: заблокирован ли (инлайн без nonce, чужой адрес).
  globalThis.__pt_cspScriptBlocked = (i) => {
    try {
      if (!__pt_cspActive()) return false;
      const el = scriptNodes[i]; if (!el) return false;
      const src = __ptGetA(el, 'src');
      if (src) { let abs = String(src); try { abs = new URL(src, (globalThis.location && location.href) || undefined).href; } catch (e) {} return __pt_cspBlocksScriptUrl(el, abs); }
      return __pt_cspBlocksInline(el);
    } catch (e) { return false; }
  };
  globalThis.__pt_endScript = () => {
    const el = document.__ptCurScript;
    document.__ptCurScript = null;
    try {
      const dt = performance.now() - __ptScriptT0;
      if (dt > 50 && typeof globalThis.__pt_noteLoaf === 'function') {
        let src = el ? __ptGetA(el, 'src') : null;
        try { if (src) src = new URL(src, location.href).href; } catch (e) {}
        const url = src || String(location.href || '');
        __pt_noteLoaf(__ptScriptT0, dt, url, 'classic-script', null, url);
      }
    } catch (e) {}
  };

  // Called after all page scripts have run: fire DOMContentLoaded then load.
  // Разбор кончился: дальше идут отложенные скрипты, и видят они уже
  // `interactive`, как в браузере.
  // Отметки навигации (domInteractive, DOMContentLoaded, load) — в тот
  // миг, когда событие и правда случилось. Мы ставили их все равными концу
  // ответа, и длительность навигации кадра выходила в два-три раза короче
  // хромовской: у браузера туда входит разбор документа и его скрипты.
  const __ptMark = (n) => { try { globalThis.__pt_markNav && __pt_markNav(n); } catch (e) {} };
  globalThis.__pt_parseDone = () => {
    if (document.__ptReady !== 'loading') return;
    __ptMark('interactive');
    document.__ptReady = 'interactive';
    try { document.dispatchEvent(__ptTrust(new Event('readystatechange'))); } catch (e) {}
  };
  globalThis.__pt_finishLoad = () => {
    // Смена готовности видна страницам: `readystatechange` браузер шлёт на
    // каждом шаге, и слушают его наравне с `DOMContentLoaded`.
    const готовность = (v) => {
      document.__ptReady = v;
      try { document.dispatchEvent(__ptTrust(new Event('readystatechange'))); } catch (e) {}
    };
    // Разбор мог кончиться раньше — перед отложенными скриптами.
    if (document.__ptReady === 'loading') { __ptMark('interactive'); готовность('interactive'); }
    __ptMark('dclStart');
    // События жизненного цикла приходят от движка, а движок здесь — браузер:
    // у настоящего `e.isTrusted` истина, и это читают первой же строкой.
    const dcl = __ptTrust(new Event('DOMContentLoaded', { bubbles: true }));
    document.dispatchEvent(dcl);
    // Событие всплывает с документа на окно, и слушают его чаще именно там:
    // `window.addEventListener('DOMContentLoaded', …)` — так api.js Turnstile
    // ставит свой авторендер. Наш всплыть не мог: окно и документ у нас разные
    // цели, — и виджет на странице с `.cf-turnstile` не появлялся вовсе.
    try {
      if (globalThis.dispatchEvent) {
        try { dcl.target = document; dcl.currentTarget = globalThis; } catch (e) {}
        globalThis.dispatchEvent(dcl);
      }
    } catch (e) {}
    __ptMark('dclEnd');
    __ptMark('complete');
    готовность('complete');
    __ptMark('loadStart');
    const load = __ptTrust(new Event('load'));
    globalThis.dispatchEvent && globalThis.dispatchEvent(load);
    // `load` в браузере доходит и до документа, и до тела.
    try { document.dispatchEvent(__ptTrust(new Event('load'))); } catch (e) {}
    __ptMark('loadEnd');
    // `pageshow` идёт следом за `load` — с `persisted: false` у обычной
    // загрузки. Его слушают те, кто отличает переход «назад» от свежей
    // загрузки; у нас его не было вовсе.
    try {
      const ps = __ptTrust(new Event('pageshow'));
      try { Object.defineProperty(ps, 'persisted', { value: false, enumerable: true, configurable: true }); }
      catch (e) {}
      globalThis.dispatchEvent && globalThis.dispatchEvent(ps);
    } catch (e) {}
  };

  // window is an EventTarget too. Таблица слушателей нужна окну всегда: с
  // цепочкой из шаблона V8 методы окно наследует от EventTarget.prototype
  // сразу, и ветка ниже не срабатывает.
  if (!Object.prototype.hasOwnProperty.call(globalThis, '__ptLis')) {
    try { Object.defineProperty(globalThis, '__ptLis', { value: Object.create(null), enumerable: false, writable: true, configurable: true }); } catch (e) {}
  }
  if (!globalThis.addEventListener) {
    globalThis.__ptLis = Object.create(null);
    globalThis.addEventListener = Node.prototype.addEventListener.bind(globalThis);
    globalThis.removeEventListener = Node.prototype.removeEventListener.bind(globalThis);
    globalThis.dispatchEvent = (ev) => {
      const l = globalThis.__ptLis[ev.type]; if (l) for (const { fn } of l.slice()) { try { fn.call(globalThis, ev); } catch (_) {} }
      return true;
    };
  }

  // ---- CDP object registry (ElementHandle / JSHandle support) --------------
  // Non-value CDP results return an `objectId` handle instead of the value; the
  // server calls these to wrap/unwrap so Puppeteer's `$`/`$eval`/`.evaluate`
  // (which pass handles by objectId) work. Names start with `__pt` so the
  // stealth layer keeps them off `Object.keys(window)`.
  const __ptObjs = new Map();
  let __ptSeq = 1;
  globalThis.__pt_wrap = (v, byValue) => {
    const t = typeof v;
    if (v === null) return { type: 'object', subtype: 'null', value: null };
    if (t === 'undefined') return { type: 'undefined' };
    if (t === 'boolean' || t === 'number' || t === 'string') return { type: t, value: v };
    if (t === 'bigint') return { type: 'bigint', unserializableValue: String(v) };
    if (byValue) {
      try { return { type: t === 'function' ? 'object' : t, value: __ptJSON.parse(__ptJSON.stringify(v)) }; }
      catch (e) { return { type: 'object', value: null }; }
    }
    const id = 'obj-' + (__ptSeq++);
    __ptObjs.set(id, v);
    if (t === 'function') return { type: 'function', objectId: id, className: 'Function', description: (v.name ? 'function ' + v.name : 'function') + '() { [native code] }' };
    let subtype, className = (v.constructor && v.constructor.name) || 'Object', description = className;
    if (Array.isArray(v)) { subtype = 'array'; className = 'Array'; description = 'Array(' + v.length + ')'; }
    else if (v.nodeType === 1) { subtype = 'node'; description = v.localName || 'element'; }
    else if (v.nodeType) { subtype = 'node'; description = (v.nodeName || 'node').toLowerCase(); }
    return { type: 'object', subtype, objectId: id, className, description };
  };
  globalThis.__pt_objGet = (id) => __ptObjs.get(id);
  globalThis.__pt_release = (id) => { __ptObjs.delete(id); };

  // Stable backendNodeId per DOM node (Puppeteer's ElementHandle needs it).
  const __ptNodes = new Map();      // backendNodeId -> node
  const __ptNodeIds = new WeakMap(); // node -> backendNodeId
  let __ptNodeSeq = 1;
  globalThis.__pt_nodeId = (n) => {
    let id = __ptNodeIds.get(n);
    if (!id) { id = __ptNodeSeq++; __ptNodeIds.set(n, id); __ptNodes.set(id, n); }
    return id;
  };
  globalThis.__pt_nodeById = (id) => __ptNodes.get(id) || null;
  globalThis.__pt_describe = (n) => {
    if (n == null || !n.nodeType) return null;
    const attrs = [];
    if (n.attributes) for (const a of n.attributes) { attrs.push(a.name); attrs.push(a.value); }
    return {
      backendNodeId: globalThis.__pt_nodeId(n), nodeId: 0, nodeType: n.nodeType,
      nodeName: n.nodeName || '', localName: n.localName || '', nodeValue: n.nodeValue || '',
      childNodeCount: (n.__ptKids || []).length, attributes: attrs
    };
  };
  // ---- synthetic layout + interaction (no real rendering) ------------------
  // There is no layout engine, so every rendered element is assigned a unique,
  // deterministic one-row box in document order. That is enough for the two
  // things drivers need: (a) a non-empty box + coordinates for visibility and
  // click-point computation, and (b) a reversible point→element mapping so an
  // Input mouse event at a computed coordinate hits the intended element.
  // Окно документа — то же окно, что и `innerWidth`/`innerHeight`: у браузера
  // `documentElement.clientWidth` и `innerWidth` описывают один прямоугольник.
  // Мы держали здесь 1280×720 независимо от них, и страница видела два разных
  // окна сразу — несостыковка, которую ищут первым делом.
  const LAYOUT = {
    W: (globalThis.innerWidth | 0) || 1280,
    H: (globalThis.innerHeight | 0) || 720,
    ROW: 20,
  };
  // Окно кадра — это его собственный `<iframe>`, а не страница: у виджета
  // Turnstile внутри 300×65, и он этот размер читает. Движок сообщает его сюда
  // сразу после создания контекста.
  // Кадр с `display: none` браузер не раскладывает вовсе: у тела внутри
  // ширина остаётся `auto`, а не числом. Признак ставит хозяйская страница,
  // когда видит, что у её `<iframe>` коробки нет.
  let __rendered = true;
  globalThis.__pt_setRendered = (on) => {
    on = !!on;
    if (on === __rendered) return;
    __rendered = on;
    __layoutBuilt = -1;
  };

  // Пересчитать раскладку этого документа. Зовёт соседний реалм: окно
  // страницы меряет узлы своего кадра, а раскладывает их кадр сам.
  globalThis.__pt_relayout = () => { try { __relayout(); } catch (e) {} };

  // Окно кадра, вынутого из документа: у браузера это закрытый контекст.
  // Страница, оставившая себе ссылку на окно, читает нули и `closed`.
  globalThis.__pt_detach = () => {
    try { Object.defineProperty(globalThis, '__ptDetached', { value: true, configurable: true }); } catch (e) {}
    try { globalThis.__pt_setViewport(0, 0); } catch (e) {}
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const put = (k, v) => { try { const d = Object.getOwnPropertyDescriptor(globalThis, k); if (d && !d.configurable) return; Object.defineProperty(globalThis, k, { get: nat(function () { return v; }, 'get ' + k), set: undefined, enumerable: true, configurable: true }); } catch (e) {} };
    put('outerWidth', 0); put('outerHeight', 0); put('closed', true); put('frameElement', null);
    put('parent', globalThis); put('top', globalThis);
  };
  globalThis.__pt_setViewport = (w, h) => {
    w = Math.max(0, Math.round(Number(w) || 0));
    h = Math.max(0, Math.round(Number(h) || 0));
    if (w === LAYOUT.W && h === LAYOUT.H && __rendered) return;
    LAYOUT.W = w; LAYOUT.H = h;
    for (const [name, value] of [['innerWidth', w], ['innerHeight', h]]) {
      try {
        const d = Object.getOwnPropertyDescriptor(globalThis, name);
        Object.defineProperty(globalThis, name, {
          value, writable: d ? d.writable !== false : true,
          enumerable: d ? d.enumerable : true, configurable: true,
        });
      } catch (e) {}
    }
    __layoutBuilt = -1;   // пересчитать коробки под новый размер
  };
  let __layoutSeq = 0;      // bumped on every DOM mutation
  let __layoutBuilt = -1;   // __layoutSeq the current boxes were built at
  let __rows = [];          // элементы в порядке наложения
  let __boxes = [];         // то же, для поиска попадания в точку
  let __mouseDownEl = null;
  let __hoverEl = null; // element the pointer is currently over

  function __markDirty() {
    __layoutSeq++;
    // Номерные свойства окна ходят за кадрами: их ровно столько, сколько
    // рамок в дереве, и правка дерева их меняет.
    if (globalThis.__pt_syncFrameSlots) { try { __pt_syncFrameSlots(); } catch (e) {} }
  }

  // --- MutationObserver ---------------------------------------------------
  // A stub that never fires is worse than none: a page waiting on a mutation
  // simply stops, with no error to explain it. Records are collected on the same
  // hooks that already mark the tree dirty and delivered in a microtask, as the
  // spec requires (callbacks must not run inside the mutation itself).
  const __observers = [];
  let __moScheduled = false;

  function __moDeliver() {
    __moScheduled = false;
    for (const o of __observers) {
      if (!o.records.length) continue;
      const batch = o.records.splice(0);
      try { o.cb(batch, o.api); } catch (e) {}
    }
  }

  function __moWatches(entry, rec) {
    if (entry.target === rec.target) return true;
    return !!entry.opts.subtree && entry.target.contains && entry.target.contains(rec.target);
  }

  function __moWants(entry, rec) {
    if (rec.type === 'childList') return !!entry.opts.childList;
    if (rec.type === 'attributes') {
      if (!entry.opts.attributes) return false;
      const filter = entry.opts.attributeFilter;
      return !filter || filter.some(a => String(a).toLowerCase() === rec.attributeName);
    }
    return !!entry.opts.characterData;
  }

  function __mutation(rec) {
    if (!__observers.length) return;
    let queued = false;
    for (const o of __observers) {
      if (!o.entries.some(e => __moWatches(e, rec) && __moWants(e, rec))) continue;
      o.records.push(rec);
      queued = true;
    }
    if (queued && !__moScheduled) {
      __moScheduled = true;
      queueMicrotask(__moDeliver);
    }
  }

  function __childListRecord(target, added, removed, prev, next) {
    return {
      type: 'childList', target,
      addedNodes: added, removedNodes: removed,
      previousSibling: prev || null, nextSibling: next || null,
      attributeName: null, attributeNamespace: null, oldValue: null,
    };
  }

  class MutationObserver {
    constructor(cb) {
      if (typeof cb !== 'function') throw new TypeError("Failed to construct 'MutationObserver': parameter 1 is not of type 'Function'.");
      const state = { cb, entries: [], records: [], api: this };
      __observers.push(state);
      Object.defineProperty(this, '__ptState', { value: state, enumerable: false });
    }
    observe(target, opts) {
      opts = opts || {};
      // The spec default: with neither childList nor attributes nor
      // characterData asked for, this is a TypeError, not a silent no-op.
      if (!opts.childList && !opts.attributes && !opts.characterData && !opts.attributeFilter) {
        throw new TypeError("Failed to execute 'observe' on 'MutationObserver': The options object must set at least one of 'attributes', 'characterData', or 'childList' to true.");
      }
      if (opts.attributeFilter) opts.attributes = true;
      this.__ptState.entries.push({ target, opts });
    }
    disconnect() { this.__ptState.entries = []; this.__ptState.records = []; }
    takeRecords() { return this.__ptState.records.splice(0); }
  }

  // --- ResizeObserver -----------------------------------------------------
  // No real layout here, so there is nothing to *re*-observe — but Chrome
  // delivers one observation as soon as you observe an element, and code that
  // waits for that first callback would otherwise hang forever.
  class ResizeObserver {
    constructor(cb) {
      const state = { cb, targets: [] };
      Object.defineProperty(this, '__ptState', { value: state, enumerable: false });
    }
    observe(target) {
      const st = this.__ptState;
      st.targets.push(target);
      queueMicrotask(() => {
        const r = (target.getBoundingClientRect && target.getBoundingClientRect()) || { width: 0, height: 0, x: 0, y: 0, top: 0, left: 0 };
        const box = [{ inlineSize: r.width, blockSize: r.height }];
        try {
          st.cb([{ target, contentRect: r, borderBoxSize: box, contentBoxSize: box, devicePixelContentBoxSize: box }], this);
        } catch (e) {}
      });
    }
    unobserve(target) { const t = this.__ptState.targets; const i = t.indexOf(target); if (i >= 0) t.splice(i, 1); }
    disconnect() { this.__ptState.targets = []; }
  }

  // --- frame plumbing -----------------------------------------------------
  // The engine drains `__pt_drainFrameQueue` each turn, builds the child context,
  // and calls back with `__pt_frameReady`. Messages travel the same road: a
  // `postMessage` in either direction becomes an op, and arrives as an event.
  const __frames = new Map();
  const __frameOps = [];
  let __nextFrameId = 1;

  // Every op costs an eval on the other side, so an unbounded queue is a way for
  // a page to spend the engine's memory: a widget that posts into its frame from
  // an interval, faster than the ops drain, once took RSS past five gigabytes.
  // Beyond the cap the newest op is dropped — a lost message degrades one widget,
  // where the alternative loses the process.
  const __MAX_FRAME_OPS = 4096;
  const __pushFrameOp = (op, into) => {
    const q = into || __frameOps;
    if (q.length < __MAX_FRAME_OPS) q.push(op);
  };

  globalThis.__pt_drainFrameQueue = () => __frameOps.splice(0);
  // Коробка элемента кадра на момент запроса: при вставке раскладки ещё нет, а
  // движок спрашивает уже после разбора документа.
  globalThis.__pt_frameBoxOf = (el) => {
    // Заданный размер важнее посчитанного: у виджета он стоит в стиле или в
    // атрибутах, а раскладка к моменту вопроса может быть ещё прошлой.
    // Заявленный ноль — ноль (у Chrome окно такого кадра 0×0), не заявлено — -1.
    const px = (v) => { const n = parseFloat(v); return Number.isFinite(n) ? Math.max(0, Math.round(n)) : -1; };
    let w = -1, h = -1;
    try { w = px(el.style && el.style.width); if (w < 0) w = px(__ptGetA(el, 'width')); } catch (e) {}
    try { h = px(el.style && el.style.height); if (h < 0) h = px(__ptGetA(el, 'height')); } catch (e) {}
    if (w >= 0 || h >= 0) return __ptJSON.stringify([w < 0 ? 300 : w, h < 0 ? 150 : h]);
    w = 0; h = 0;
    // Только заявленный размер: спросить раскладку значит построить её прямо
    // сейчас, посреди загрузки, и заморозить в недостроенном виде — страница
    // потом получала нулевые коробки. Не заявлен — размер по умолчанию, как у
    // браузера для кадра без размеров.
    return __ptJSON.stringify([w || 300, h || 150]);
  };
  globalThis.__pt_frameBox = (id) => {
    const st = __frames.get(id);
    return st && st.el ? __pt_frameBoxOf(st.el) : '[300,150]';
  };

  // --- dynamically inserted <script src> -----------------------------------
  // The element cannot fetch; the engine can. Each insertion becomes an op the
  // driver picks up, fetches against the document's own base URL and cookies, and
  // evaluates in this context — then says how it went, so `onload`/`onerror` fire
  // where the page expects them.
  const __scriptEls = new Map();
  const __scriptOps = [];
  let __nextScriptId = 1;

  globalThis.__pt_drainScriptQueue = () => __scriptOps.splice(0);

  // Пока исполняется скрипт, вставленный страницей, `document.currentScript` —
  // он сам, как у встроенного в разметку. У нас там было пусто, и api.js
  // Turnstile не находил собственный адрес, а с ним — свою запись Resource
  // Timing: у браузера она уходит виджету целиком, у нас не уходила вовсе.
  // У модуля `currentScript` пуст и у браузера — его не ставим.
  globalThis.__pt_scriptStart = (id) => {
    const el = __scriptEls.get(id);
    if (el) document.__ptCurScript = el;
  };

  globalThis.__pt_scriptDone = (id, ok) => {
    const el = __scriptEls.get(id);
    // Скрипт отработал — `currentScript` снова пуст, и `onload` его уже не
    // видит, как и у браузера.
    if (el && document.__ptCurScript === el) document.__ptCurScript = null;
    if (!el) return;
    __scriptEls.delete(id);
    const ev = { type: ok ? 'load' : 'error', target: el, currentTarget: el, isTrusted: true };
    // Рассылка сама зовёт `on…`; вызывать его ещё и отдельно — значит сработать
    // дважды на каждом скрипте.
    try { el.dispatchEvent && el.dispatchEvent(ev); } catch (e) {}
  };

  // Tear down a frame whose element left the document, and let the element be
  // connected again later as a fresh one.
  const __ptDisconnectFrame = (el) => {
    const id = el.__ptFrameId;
    if (!id) return;
    __frames.delete(id);
    try { Object.defineProperty(el, '__ptFrameId', { value: 0, configurable: true, enumerable: false }); } catch (e) {}
    __frameOps.push({ op: 'close', id });
  };

  // The cross-origin window surface, and nothing more: `postMessage`, the frame
  // tree accessors, `closed`. Reading anything else from another origin throws in
  // a browser; answering `undefined` would give us away, so the object simply
  // carries what is allowed. Messages sent before the document exists are held
  // and flushed on ready, as a browser queues them against `about:blank`.
  const __frameWindow = (id, st) => ({
    postMessage: (data, targetOrigin) => {
      const op = { op: 'post', id, data: __pt_cloneEncode(data), toParent: false, targetOrigin: String(targetOrigin || '*') };
      __pushFrameOp(op, st.ready ? __frameOps : st.pending);
    },
    get closed() { return false; },
    get frames() { return st.win; },
    get length() { return 0; },
    get parent() { return globalThis; },
    get top() { return globalThis; },
    get opener() { return null; },
    get self() { return st.win; },
    get window() { return st.win; },
  });

  globalThis.__pt_frameReady = (id, origin) => {
    const st = __frames.get(id);
    if (!st) return;
    st.ready = true;
    st.sameOrigin = !!(globalThis.location && origin === location.origin);
    for (const op of st.pending.splice(0)) __pushFrameOp(op);
    const ev = { type: 'load', target: st.el, currentTarget: st.el, isTrusted: true };
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
  };

  globalThis.__pt_frameFailed = (id) => {
    const st = __frames.get(id);
    if (!st) return;
    __frames.delete(id);
    const ev = { type: 'error', target: st.el, currentTarget: st.el, isTrusted: true };
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
  };

  // A `message` event arriving from the other side of a frame boundary.
  globalThis.__pt_deliverMessage = (raw, origin, fromFrameId) => {
    // Значение приезжает разобранным литералом — оживляем из него те же типы.
    let data = raw;
    try { data = globalThis.__pt_cloneRevive ? __pt_cloneRevive(raw) : raw; } catch (e) {}
    const source = fromFrameId ? (__frames.get(fromFrameId) || {}).win || null : (globalThis.parent === globalThis ? null : globalThis.parent);
    const ev = {
      type: 'message', data, origin: String(origin || ''), lastEventId: '',
      source, ports: [], isTrusted: true, target: globalThis, currentTarget: globalThis,
    };
    try { globalThis.dispatchEvent && globalThis.dispatchEvent(ev); } catch (e) {}
  };

  // Inside a frame, `parent`/`top` are the embedder, and `postMessage` on them
  // goes back up. The engine calls this right after creating the child context
  // and before its document exists — a context cannot know it is a frame while
  // its own bootstrap is still running.
  globalThis.__pt_markAsFrame = (id) => {
    globalThis.__pt_frameId = id;
    const up = {
      postMessage: (data) => {
        __pushFrameOp({ op: 'post', data: __pt_cloneEncode(data), toParent: true });
      },
      get closed() { return false; },
      get frames() { return up; },
      get length() { return 0; },
      get self() { return up; },
      get window() { return up; },
    };
    try {
      Object.defineProperty(globalThis, 'parent', { value: up, configurable: true });
      Object.defineProperty(globalThis, 'top', { value: up, configurable: true });
    } catch (e) {}
    // Из стороннего кадра свой `<iframe>` не виден: `frameElement` — null, как
    // и `opener`; у нас их не было вовсе, и страница читала undefined.
    for (const k of ['frameElement', 'opener']) {
      try {
        const g = function () { return null; };
        try { Object.defineProperty(g, 'name', { value: 'get ' + k, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, k, { get: globalThis.__pt_native ? __pt_native(g) : g, set: undefined, enumerable: true, configurable: true });
      } catch (e) {}
    }
  };

  // --- tree traversal ------------------------------------------------------
  // `NodeFilter` + `createTreeWalker`/`createNodeIterator`. Absent, this cost us
  // every Cloudflare challenge: the Turnstile loader answers its widget's
  // `requestExtraParams` with a page report that walks the document through a
  // TreeWalker, so `NodeFilter is not defined` threw inside a `message` listener
  // — where the exception is swallowed by design — and the reply the widget waits
  // for was never sent. It sat there answering heartbeats, forever, saying
  // nothing about why.
  const FILTER_ACCEPT = 1, FILTER_REJECT = 2, FILTER_SKIP = 3;
  const NodeFilter = {
    FILTER_ACCEPT, FILTER_REJECT, FILTER_SKIP,
    SHOW_ALL: 0xFFFFFFFF, SHOW_ELEMENT: 0x1, SHOW_ATTRIBUTE: 0x2, SHOW_TEXT: 0x4,
    SHOW_CDATA_SECTION: 0x8, SHOW_ENTITY_REFERENCE: 0x10, SHOW_ENTITY: 0x20,
    SHOW_PROCESSING_INSTRUCTION: 0x40, SHOW_COMMENT: 0x80, SHOW_DOCUMENT: 0x100,
    SHOW_DOCUMENT_TYPE: 0x200, SHOW_DOCUMENT_FRAGMENT: 0x400, SHOW_NOTATION: 0x800,
  };

  // The filter verdict for one node: the `whatToShow` bitmask first (a node it
  // hides is skipped without ever reaching the callback), then the caller's
  // filter, which may be a function or an object with `acceptNode`.
  const __ptVerdict = (walker, node) => {
    if (!((1 << (node.nodeType - 1)) & walker.__ptShow)) return FILTER_SKIP;
    const f = walker.__ptFilter;
    if (!f) return FILTER_ACCEPT;
    const v = typeof f === 'function' ? f(node) : (f.acceptNode ? f.acceptNode(node) : FILTER_ACCEPT);
    return v === undefined || v === null ? FILTER_ACCEPT : v;
  };

  // The node after `node` in document order, without leaving `root`.
  const __ptFollowing = (node, root, skipChildren) => {
    if (!skipChildren && node.__ptKids && node.__ptKids.length) return node.__ptKids[0];
    for (let n = node; n && n !== root; n = n.parentNode) {
      if (n.nextSibling) return n.nextSibling;
    }
    return null;
  };

  class TreeWalker {
    constructor(root, whatToShow, filter) {
      this.__ptRoot = root;
      this.__ptShow = whatToShow === undefined ? 0xFFFFFFFF : whatToShow >>> 0;
      this.__ptFilter = filter || null;
      this.__ptCur = root;
    }
    get root() { return this.__ptRoot; }
    get whatToShow() { return this.__ptShow; }
    get filter() { return this.__ptFilter; }
    get currentNode() { return this.__ptCur; }
    set currentNode(n) { this.__ptCur = n; }

    nextNode() {
      let node = this.__ptCur, skipKids = false;
      for (;;) {
        node = __ptFollowing(node, this.__ptRoot, skipKids);
        if (!node) return null;
        const v = __ptVerdict(this, node);
        if (v === FILTER_ACCEPT) { this.__ptCur = node; return node; }
        skipKids = v === FILTER_REJECT;
      }
    }
    previousNode() {
      let node = this.__ptCur;
      while (node && node !== this.__ptRoot) {
        let prev = node.previousSibling;
        if (prev) {
          while (prev.__ptKids && prev.__ptKids.length) prev = prev.__ptKids[prev.__ptKids.length - 1];
          node = prev;
        } else {
          node = node.parentNode;
          if (!node || node === this.__ptRoot) return null;
        }
        if (__ptVerdict(this, node) === FILTER_ACCEPT) { this.__ptCur = node; return node; }
      }
      return null;
    }
    parentNode() {
      for (let n = this.__ptCur; n && n !== this.__ptRoot; ) {
        n = n.parentNode;
        if (!n) return null;
        if (__ptVerdict(this, n) === FILTER_ACCEPT) { this.__ptCur = n; return n; }
        if (n === this.__ptRoot) break;
      }
      return null;
    }
    firstChild() { return this.__ptChild(0); }
    lastChild() { return this.__ptChild(-1); }
    __ptChild(from) {
      const kids = this.__ptCur.__ptKids || [];
      const list = from === 0 ? kids : kids.slice().reverse();
      for (const c of list) {
        if (__ptVerdict(this, c) === FILTER_ACCEPT) { this.__ptCur = c; return c; }
      }
      return null;
    }
    nextSibling() { return this.__ptSibling('nextSibling'); }
    previousSibling() { return this.__ptSibling('previousSibling'); }
    __ptSibling(dir) {
      for (let n = this.__ptCur[dir]; n; n = n[dir]) {
        if (__ptVerdict(this, n) === FILTER_ACCEPT) { this.__ptCur = n; return n; }
      }
      return null;
    }
  }

  class NodeIterator {
    constructor(root, whatToShow, filter) {
      this.__ptRoot = root;
      this.__ptShow = whatToShow === undefined ? 0xFFFFFFFF : whatToShow >>> 0;
      this.__ptFilter = filter || null;
      this.__ptRef = root;
      this.__ptBefore = true;
    }
    get root() { return this.__ptRoot; }
    get whatToShow() { return this.__ptShow; }
    get filter() { return this.__ptFilter; }
    get referenceNode() { return this.__ptRef; }
    get pointerBeforeReferenceNode() { return this.__ptBefore; }
    nextNode() {
      let node = this.__ptRef;
      if (this.__ptBefore) { this.__ptBefore = false; }
      else { node = __ptFollowing(node, this.__ptRoot, false); }
      while (node) {
        if (__ptVerdict(this, node) === FILTER_ACCEPT) { this.__ptRef = node; return node; }
        node = __ptFollowing(node, this.__ptRoot, false);
      }
      return null;
    }
    previousNode() { return null; }
    detach() {}
  }

  Document.prototype.createTreeWalker = function (root, whatToShow, filter) {
    return new TreeWalker(root || this, whatToShow, filter);
  };
  Document.prototype.createNodeIterator = function (root, whatToShow, filter) {
    return new NodeIterator(root || this, whatToShow, filter);
  };
  globalThis.NodeFilter = NodeFilter;
  globalThis.TreeWalker = TreeWalker;
  globalThis.NodeIterator = NodeIterator;

  // Assigned here, after the declarations (a class stays in its temporal dead
  // zone until then). These override the stealth layer's inert stubs: with a
  // document present there is a real tree to watch.
  globalThis.CustomElementRegistry = CustomElementRegistry;
  globalThis.customElements = new CustomElementRegistry();
  // `document.createRange()` был именем без тела и отдавал undefined. Полный
  // Range нам не нужен, но объект должен быть объектом своего интерфейса:
  // страницы меряют текст через `range.getBoundingClientRect()`, а сборщики
  // отпечатка спрашивают у него имя.
  const __range = () => {
    const R = globalThis.Range;
    const r = Object.create(R && R.prototype ? R.prototype : Object.prototype);
    let start = document, startOff = 0, end = document, endOff = 0;
    Object.defineProperties(r, {
      startContainer: { get: () => start, enumerable: true, configurable: true },
      endContainer: { get: () => end, enumerable: true, configurable: true },
      startOffset: { get: () => startOff, enumerable: true, configurable: true },
      endOffset: { get: () => endOff, enumerable: true, configurable: true },
      collapsed: { get: () => start === end && startOff === endOff, enumerable: true, configurable: true },
      commonAncestorContainer: { get: () => start, enumerable: true, configurable: true },
    });
    Object.assign(r, {
      setStart(n, o) { start = n; startOff = o | 0; },
      setEnd(n, o) { end = n; endOff = o | 0; },
      setStartBefore(n) { start = n.parentNode || n; startOff = 0; },
      setStartAfter(n) { start = n.parentNode || n; startOff = 0; },
      setEndBefore(n) { end = n.parentNode || n; endOff = 0; },
      setEndAfter(n) { end = n.parentNode || n; endOff = 0; },
      selectNode(n) { start = end = n.parentNode || n; startOff = 0; endOff = 0; },
      selectNodeContents(n) { start = end = n; startOff = 0; endOff = (n.childNodes || []).length; },
      collapse(toStart) { if (toStart) { end = start; endOff = startOff; } else { start = end; startOff = endOff; } },
      cloneRange() { const c = __range(); c.setStart(start, startOff); c.setEnd(end, endOff); return c; },
      detach() {},
      toString() { return ''; },
      // Страницы меряют текст через диапазон — это второй по ходовости способ
      // после `measureText`, — а он отвечал нулями, то есть «текста нет».
      // Прямоугольник тут не один: браузер отдаёт по одному на каждую строку,
      // и по ним видно, как текст разложился.
      getClientRects() {
        const node = start;
        const el = node && node.nodeType === ELEMENT_NODE ? node
                 : (node && node.parentNode) || null;
        const b = el && el.nodeType === ELEMENT_NODE ? __boxOf(el) : null;
        if (!b) return __ptRectList([]);
        const h = (b.asc || 0) + (b.desc || 0);
        const rows = (b.lines && b.lines.length ? b.lines : [{ width: b.cw }]);
        return __ptRectList(rows.map((ln, i) =>
          new DOMRect(b.cx, b.cy + i * (b.line || h), ln.width, h)));
      },
      getBoundingClientRect() {
        const list = this.getClientRects();
        if (!list.length) return { x: 0, y: 0, width: 0, height: 0, top: 0, right: 0, bottom: 0, left: 0 };
        let l = Infinity, t = Infinity, r2 = -Infinity, b2 = -Infinity;
        for (const q of list) { l = Math.min(l, q.left); t = Math.min(t, q.top); r2 = Math.max(r2, q.right); b2 = Math.max(b2, q.bottom); }
        return { x: l, y: t, left: l, top: t, right: r2, bottom: b2, width: r2 - l, height: b2 - t };
      },
      deleteContents() {}, extractContents() { return document.createDocumentFragment(); },
      cloneContents() { return document.createDocumentFragment(); },
      insertNode(n) { if (start && start.appendChild) start.appendChild(n); },
      surroundContents() {},
      isPointInRange() { return false; },
      comparePoint() { return 0; },
      intersectsNode() { return false; },
    });
    return r;
  };
  Document.prototype.createRange = function createRange() { return __range(); };

  // Таблица формы интерфейсов кладёт на `HTMLImageElement.prototype` свой
  // отражатель `src`, и он перебивает наш — тот, что отправляет запрос. Ставим
  // настоящий обратно, поверх заглушки.
  try {
    const IP = globalThis.HTMLImageElement && globalThis.HTMLImageElement.prototype;
    if (IP) {
      Object.defineProperty(IP, 'src', {
        get() { return this.__ptUrlAttr ? this.__ptUrlAttr('src') : (__ptGetA(this, 'src') || ''); },
        set(v) {
          __ptSetA(this, 'src', v);
          if (this.__ptLoadImage) this.__ptLoadImage();
        },
        enumerable: true, configurable: true,
      });
    }
  } catch (e) {}

  // `new Image()` — фабрика, как и `Audio`: браузер отдаёт настоящий элемент
  // `<img>`. У нас под этим именем лежала заготовка из таблицы имён — с
  // правильной меткой, но без нашего класса, — поэтому `img.src = …` был
  // обычным присваиванием и в сеть не шёл ничего.
  // Строгие: у фабрики браузера нет собственных `arguments`/`caller`.
  const __ptImageCtor = (function () {
    'use strict';
    return function Image(w, h) {
      const O = globalThis.__pt_orig;
      const el = O && O.createElement
        ? O.createElement.call(document, 'img')
        : document.createElement('img');
      if (w !== undefined) __ptSetAttr.call(el, 'width', String(w | 0));
      if (h !== undefined) __ptSetAttr.call(el, 'height', String(h | 0));
      return el;
    };
  })();
  try {
    Object.defineProperty(globalThis, 'Image', { value: __ptImageCtor, writable: true, enumerable: false, configurable: true });
    Object.defineProperty(globalThis.Image, 'prototype', {
      value: globalThis.HTMLImageElement ? globalThis.HTMLImageElement.prototype : Object.prototype,
      writable: false, enumerable: false, configurable: false,
    });
  } catch (e) {}

  // `new Audio()` — это не свой интерфейс, а фабрика: браузер отдаёт
  // HTMLAudioElement, и `Object.prototype.toString` по нему говорит именно это.
  globalThis.Audio = (function () {
    'use strict';
    return function Audio(src) {
      const O = globalThis.__pt_orig;
      const el = O && O.createElement
        ? O.createElement.call(document, 'audio')
        : document.createElement('audio');
      if (src !== undefined) __ptSetAttr.call(el, 'src', String(src));
      return el;
    };
  })();
  try {
    Object.defineProperty(globalThis.Audio, 'prototype', {
      value: globalThis.HTMLAudioElement ? globalThis.HTMLAudioElement.prototype : Object.prototype,
      writable: false, enumerable: false, configurable: false,
    });
  } catch (e) {}

  globalThis.MutationObserver = MutationObserver;
  globalThis.ResizeObserver = ResizeObserver;

  // Каждый элемент называет свой интерфейс: в браузере `<canvas>` — это
  // `[object HTMLCanvasElement]`, а не `[object Object]`. Классов на тег у нас
  // нет, поэтому имя выводится из тега — этого хватает и для toString, и для
  // проверок, которые на нём построены.
  const __IFACE = {
    a: 'HTMLAnchorElement', area: 'HTMLAreaElement', audio: 'HTMLAudioElement',
    base: 'HTMLBaseElement', body: 'HTMLBodyElement', br: 'HTMLBRElement',
    button: 'HTMLButtonElement', canvas: 'HTMLCanvasElement', data: 'HTMLDataElement',
    datalist: 'HTMLDataListElement', dialog: 'HTMLDialogElement', div: 'HTMLDivElement',
    dl: 'HTMLDListElement', embed: 'HTMLEmbedElement', fieldset: 'HTMLFieldSetElement',
    form: 'HTMLFormElement', head: 'HTMLHeadElement', hr: 'HTMLHRElement',
    html: 'HTMLHtmlElement', iframe: 'HTMLIFrameElement', img: 'HTMLImageElement',
    input: 'HTMLInputElement', label: 'HTMLLabelElement', legend: 'HTMLLegendElement',
    li: 'HTMLLIElement', link: 'HTMLLinkElement', map: 'HTMLMapElement',
    menu: 'HTMLMenuElement', meta: 'HTMLMetaElement', meter: 'HTMLMeterElement',
    object: 'HTMLObjectElement', ol: 'HTMLOListElement', optgroup: 'HTMLOptGroupElement',
    option: 'HTMLOptionElement', output: 'HTMLOutputElement', p: 'HTMLParagraphElement',
    picture: 'HTMLPictureElement', pre: 'HTMLPreElement', progress: 'HTMLProgressElement',
    q: 'HTMLQuoteElement', script: 'HTMLScriptElement', select: 'HTMLSelectElement',
    slot: 'HTMLSlotElement', source: 'HTMLSourceElement', span: 'HTMLSpanElement',
    style: 'HTMLStyleElement', table: 'HTMLTableElement', tbody: 'HTMLTableSectionElement',
    td: 'HTMLTableCellElement', template: 'HTMLTemplateElement', textarea: 'HTMLTextAreaElement',
    tfoot: 'HTMLTableSectionElement', th: 'HTMLTableCellElement', thead: 'HTMLTableSectionElement',
    title: 'HTMLTitleElement', tr: 'HTMLTableRowElement', track: 'HTMLTrackElement',
    ul: 'HTMLUListElement', video: 'HTMLVideoElement',
  };
  const __tagFor = (el) => {
    const local = el.__ptLocal || '';
    if (__IFACE[local]) return __IFACE[local];
    // Имя с дефисом — пользовательский элемент (HTMLElement); неизвестный
    // одиночный тег браузер считает HTMLUnknownElement.
    if (local.indexOf('-') > 0) return 'HTMLElement';
    return /^(abbr|address|article|aside|b|bdi|bdo|cite|code|dd|dfn|dt|em|figcaption|figure|footer|h1|h2|h3|h4|h5|h6|header|hgroup|i|ins|del|kbd|main|mark|nav|noscript|rp|rt|ruby|s|samp|section|small|strong|sub|summary|sup|time|u|var|wbr|details|blockquote|caption|colgroup|col)$/.test(local)
      ? 'HTMLElement' : 'HTMLUnknownElement';
  };
  for (const [C, name] of [[Node, 'Node'], [Element, 'Element'], [Text, 'Text'], [Comment, 'Comment'],
    [Document, 'Document'], [DocumentFragment, 'DocumentFragment'], [ShadowRoot, 'ShadowRoot']]) {
    if (!C) continue;
    try {
      // На самом прототипе — его имя (`[object Element]`), на экземпляре —
      // имя интерфейса тега.
      Object.defineProperty(C.prototype, Symbol.toStringTag, name
        ? { value: name, configurable: true }
        : { get: function () { if (this === C.prototype) return C === Element ? 'Element' : 'Node'; return this.nodeType === ELEMENT_NODE ? __tagFor(this) : 'Node'; }, configurable: true });
    } catch (e) {}
  }

  for (const C of [Element, Text, Comment]) {
    Object.defineProperty(C.prototype, 'remove', { value: __removeSelf, writable: true, configurable: true });
  }

  // Now that every interface exists, publish their members the way the platform
  // does — enumerable on the prototype (see `__webidl` above).
  for (const name of ['Node', 'Element', 'HTMLElement', 'Document', 'Text', 'Comment',
    'DocumentFragment', 'ShadowRoot', 'Event', 'UIEvent', 'MouseEvent', 'PointerEvent',
    'KeyboardEvent', 'InputEvent', 'FocusEvent', 'MessageEvent', 'CustomEvent',
    'MutationObserver', 'ResizeObserver', 'IntersectionObserver', 'NodeFilter',
    'TreeWalker', 'NodeIterator', 'DOMTokenList', 'NamedNodeMap', 'Attr',
    'HTMLCollection', 'NodeList', 'CSSStyleDeclaration', 'DOMRect', 'Worker',
    'XMLHttpRequest', 'EventTarget', 'Blob', 'File', 'FileReader', 'FormData',
    'Headers', 'Request', 'Response', 'URL', 'URLSearchParams', 'ReadableStream',
    'WritableStream', 'TransformStream', 'BroadcastChannel', 'MessageChannel',
    'MessagePort', 'AbortController', 'AbortSignal', 'DOMException']) {
    __webidl(globalThis[name]);
  }

  // Теги, которые не рисуют ничего: занимать место в раскладке они не вправе.
  // Пока занимали, содержимое фрейма съезжало на их высоту, и точка попадала
  // в <style> вместо кнопки.
  const __UNRENDERED = new Set(['HEAD', 'META', 'STYLE', 'SCRIPT', 'LINK', 'TITLE',
    'BASE', 'NOSCRIPT', 'TEMPLATE', 'PARAM', 'SOURCE', 'TRACK']);

  // Коробки нет вовсе: `display: none` и то, что браузер не раскладывает
  // никогда. Не путать с невидимым — `visibility: hidden` место занимает, и
  // браузер отдаёт у такого элемента настоящий прямоугольник.
  function __isUnboxed(el) {
    if (__UNRENDERED.has(el.tagName)) return true;
    if (__noneBySheet.has(el)) return true;
    if (el.hasAttribute && __ptHasA(el, 'hidden')) return true;
    // Скрытое поле формы ничего не занимает — и строки тоже.
    if (el.tagName === 'INPUT' && /^hidden$/i.test(__ptGetA(el, 'type') || '')) return true;
    const s = el.style;
    if (s && String(s.display || '').toLowerCase() === 'none') return true;
    return false;
  }

  function __isHiddenEl(el) {
    if (__isUnboxed(el)) return true;
    if (__hiddenBySheet.has(el)) return true;
    const s = el.style;
    if (s) {
      const v = String(s.visibility || '').toLowerCase();
      if (v === 'hidden' || v === 'collapse') return true;
    }
    return false;
  }

  // Каскад. Раньше из таблиц вычитывались одним регулярным выражением только
  // правила, которые прячут, — всё остальное страница объявляла впустую:
  // `getComputedStyle` элемента с `width: 200px` в таблице отвечал шириной
  // окна, противореча собственному CSS страницы. Теперь правила разбираются
  // по-настоящему: селекторы сопоставляются, специфичность считается, а
  // объявления накладываются в порядке возрастания веса.
  const __SPEC_ATTR = /\[[^\]]*\]/g;
  function __specificity(sel) {
    const list = __selCompiled(sel);
    if (list && list.length === 1) {
      const [a, b, c] = list[0].spec;
      return a * 10000 + b * 100 + c;
    }
    const s = String(sel).replace(__SPEC_ATTR, '[]');
    const ids = (s.match(/#[\w-]+/g) || []).length;
    const cls = (s.match(/\.[\w-]+|\[\]|:(?!:)[a-zA-Z-]+/g) || []).length;
    const tags = (s.match(/(?:^|[\s>+~])([a-zA-Z][\w-]*)/g) || []).length
               + (s.match(/::[\w-]+/g) || []).length;
    return ids * 10000 + cls * 100 + tags;
  }

  // Условие @media: считаем то, что действительно влияет на размеры, — ширину
  // и высоту окна. Про остальное честнее ответить «нет», чем применить наугад.
  function __mediaApplies(cond) {
    const c = String(cond || '').toLowerCase().trim();
    if (!c || c === 'all' || c === 'screen') return true;
    if (/print|speech/.test(c)) return false;
    if (/prefers-color-scheme:\s*dark/.test(c)) return false;
    if (/prefers-reduced-motion:\s*reduce/.test(c)) return false;
    let ok = true;
    const px = (v) => parseFloat(v) || 0;
    for (const m of c.matchAll(/\((min|max)-(width|height):\s*([\d.]+)px\)/g)) {
      const have = m[2] === 'width' ? LAYOUT.W : LAYOUT.H;
      ok = ok && (m[1] === 'min' ? have >= px(m[3]) : have <= px(m[3]));
    }
    return ok;
  }

  let __rules = [];                       // {root, sel, spec, order, style}
  let __foreignRules = new WeakMap();     // документ → его правила
  let __styleCache = new WeakMap();
  // Кегль и наследуемое значение считаются обходом предков, а спрашивают их
  // у каждого узла по нескольку раз за проход: на три сотни узлов выходило
  // под полторы тысячи обходов. Живут эти ответы ровно столько же, сколько
  // каскад, — до следующей сборки правил.
  let __passFont = new WeakMap();
  let __passInherit = new WeakMap();
  let __passCustom = new WeakMap();
  let __hiddenBySheet = new WeakSet();
  let __noneBySheet = new WeakSet();

  // Правила одного дерева: таблицы стилей, которые в нём лежат, разобранные
  // в плоский список. Вынесено из сбора, потому что документов бывает больше
  // одного — см. `__rulesFor`.
  function __gatherRules(docEl, out) {
    const state = { order: out.length };
    const take = (root, rules) => {
      for (const r of rules || []) {
        if (r.type === 4 || r.type === 12) {          // @media / @supports
          if (r.type !== 4 || __mediaApplies(r.conditionText)) take(root, r.cssRules);
          continue;
        }
        if (r.type !== 1 || !r.selectorText) continue;
        for (const one of __selSplit(r.selectorText)) {
          const sel = one.trim();
          if (!sel) continue;
          out.push({ root, sel, spec: __specificity(sel), order: state.order++, rule: r });
        }
      }
    };
    const sheetsOf = (node, root) => {
      for (const n of (node.__ptKids || [])) {
        if (n.nodeType !== ELEMENT_NODE) continue;
        if ((n.tagName === 'STYLE' || (n.tagName === 'LINK' && n.__ptSheetText)) && n.sheet) {
          take(root, n.sheet.cssRules);
        }
        if (n.__ptShadow) sheetsOf(n.__ptShadow, n.__ptShadow);
        sheetsOf(n, root);
      }
    };
    sheetsOf(docEl, docEl);
    return out;
  }

  // Чьи правила касаются этого элемента. Документ бывает не один: страница
  // делает `document.implementation.createHTMLDocument()` — или заводит
  // разборщик разметки — и меряет вычисленный стиль тела там. Стили хозяйской
  // страницы туда не достают, и браузер отвечает умолчаниями: чёрным цветом и
  // шестнадцатью пикселями. Мы отвечали цветом и кеглем страницы, и весь
  // перечисленный стиль расходился с браузерным — челлендж снимает его целиком.
  /// Ключ правила — по самому правому составному: id, класс или тег. Каскад
  /// спрашивает только правила со «своими» ключами, как браузер: сверять
  /// каждое из трёх тысяч правил chess.com с каждым элементом стоило по сотне
  /// миллисекунд на всякую перераскладку.
  function __ruleKey(sel) {
    let depth = 0, q = null, start = 0;
    for (let i = 0; i < sel.length; i++) {
      const c = sel[i];
      if (c === '\\') { i++; continue; }
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (depth === 0 && (c === ' ' || c === '>' || c === '+' || c === '~' || c === '\t' || c === '\n')) start = i + 1;
    }
    const comp = sel.slice(start);
    let flat = '';
    depth = 0;
    for (const c of comp) {
      if (c === '(' || c === '[') { depth++; continue; }
      if (c === ')' || c === ']') { depth--; continue; }
      if (depth === 0) flat += c;
    }
    if (flat.indexOf('\\') >= 0) return null;
    let m = /#([\w-]+)/.exec(flat);
    if (m) return 'i' + m[1];
    m = /\.([\w-]+)/.exec(flat);
    if (m) return 'c' + m[1];
    m = /^([a-zA-Z][\w-]*)/.exec(flat);
    if (m) return 't' + m[1].toLowerCase();
    return null;
  }
  const __ruleIndexes = new WeakMap();
  function __ruleIndex(rules) {
    let ix = __ruleIndexes.get(rules);
    if (ix && ix.n === rules.length) return ix;
    ix = { n: rules.length, keyed: new Map(), any: [] };
    for (const r of rules) {
      const k = __ruleKey(r.sel);
      if (k == null) { ix.any.push(r); continue; }
      let list = ix.keyed.get(k);
      if (!list) ix.keyed.set(k, (list = []));
      list.push(r);
    }
    __ruleIndexes.set(rules, ix);
    return ix;
  }
  /// Правила, которые могут подойти элементу.
  // Корень дерева элемента: теневой корень или элемент документа. Таблицы
  // стилей действуют только в своём дереве — стили документа в теневое не
  // достают, и наоборот (у Chrome div в теневом корне не видит `.x{display:flex}`
  // из <style> страницы).
  function __treeRootOf(el) {
    let n = el;
    while (n) {
      const p = n.parentNode;
      if (!p) return n.nodeType === 11 && n.__ptHost ? n : (n.ownerDocument && n.ownerDocument.documentElement) || n;
      if (p.nodeType === 11 && p.__ptHost) return p;
      n = p;
    }
    return null;
  }
  function __candidateRules(el) {
    const ix = __ruleIndex(__rulesFor(el.ownerDocument));
    const root = __treeRootOf(el);
    const docEl = el.ownerDocument && el.ownerDocument.documentElement;
    const inScope = (r) => !r.root || r.root === root || (root === docEl && r.root === docEl) || (root && root.nodeType !== 11 && r.root && r.root.nodeType !== 11);
    const out = ix.any.filter(inScope);
    const add = (k) => { const l = ix.keyed.get(k); if (l) for (const r of l) if (inScope(r)) out.push(r); };
    add('t' + String(el.localName || '').toLowerCase());
    const id = __ptGetA(el, 'id');
    if (id) add('i' + id);
    const cls = __ptGetA(el, 'class');
    if (cls) {
      const seen = new Set();
      for (const c of cls.split(/[\t\n\f\r ]+/)) if (c && !seen.has(c)) { seen.add(c); add('c' + c); }
    }
    return out;
  }

  /// Карта объявлений правила как написано.
  function __ruleMap(rr) {
    const rule = rr.rule;
    if (!rule) return null;
    if (rule.__ptDecls) return rule.__ptDecls;
    const d = rule.style;
    const raw = d && __declRaw.get(d);
    return raw ? raw() : null;
  }

  function __rulesFor(doc) {
    if (!doc || doc === globalThis.document) return __rules;
    let hit = __foreignRules.get(doc);
    if (hit) return hit;
    hit = doc.documentElement ? __gatherRules(doc.documentElement, []) : [];
    __foreignRules.set(doc, hit);
    return hit;
  }

  function __collectHidden() {
    __rules = [];
    __styleCache = new WeakMap();
    __passFont = new WeakMap();
    __passInherit = new WeakMap();
    __passCustom = new WeakMap();
    __hiddenBySheet = new WeakSet();
    __noneBySheet = new WeakSet();
    __foreignRules = new WeakMap();
    const doc = globalThis.document;
    if (!doc || !doc.documentElement) return;
    __gatherRules(doc.documentElement, __rules);
    // Спрятанное собирается тем же проходом: скрытие — просто одно из
    // объявлений, и отдельного правила для него больше не нужно.
    for (const r of __rules) {
      const d = __ruleMap(r);
      if (!d) continue;
      const disp = String(d.get('display') || '').toLowerCase();
      const vis = String(d.get('visibility') || '').toLowerCase();
      if (disp !== 'none' && vis !== 'hidden' && vis !== 'collapse') continue;
      try {
        for (const el of query(r.root, r.sel)) {
          __hiddenBySheet.add(el);
          if (disp === 'none') __noneBySheet.add(el);
        }
      } catch (e) {}
    }
  }

  /// Объявления, дошедшие до элемента: сначала таблицы по весу, потом его
  /// собственный атрибут `style`.
  /// Свойства, которые в SVG пишут атрибутами. Список Chrome 151.
  const SVG_PRESENTATION = ['alignment-baseline', 'baseline-shift', 'clip-path', 'clip-rule',
    'color', 'color-interpolation', 'color-interpolation-filters', 'cursor', 'direction',
    'display', 'dominant-baseline', 'fill', 'fill-opacity', 'fill-rule', 'filter',
    'flood-color', 'flood-opacity', 'font-family', 'font-size', 'font-size-adjust',
    'font-stretch', 'font-style', 'font-variant', 'font-weight', 'image-rendering',
    'letter-spacing', 'lighting-color', 'marker-end', 'marker-mid', 'marker-start', 'mask',
    'mask-type', 'opacity', 'overflow', 'paint-order', 'pointer-events', 'shape-rendering',
    'stop-color', 'stop-opacity', 'stroke', 'stroke-dasharray', 'stroke-dashoffset',
    'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit', 'stroke-opacity',
    'stroke-width', 'text-anchor', 'text-decoration', 'text-overflow', 'text-rendering',
    'transform-origin', 'unicode-bidi', 'vector-effect', 'visibility', 'white-space',
    'word-spacing', 'writing-mode'];
  const SVG_LENGTH_ATTRS = new Set(['font-size', 'letter-spacing', 'word-spacing',
    'stroke-width', 'stroke-dashoffset', 'baseline-shift']);

  function __cascadeFor(el) {
    if (!el || el.nodeType !== ELEMENT_NODE) return new Map();
    const hit = __styleCache.get(el);
    if (hit) return hit;
    const out = new Map();
    // В SVG свойства пишут атрибутами, и браузер считает их объявлениями
    // самого низкого веса: `<text font-size="150">` меряется полутора сотнями
    // пикселей, а не шестнадцатью.
    if (el.__ptNS === 'http://www.w3.org/2000/svg' && el.hasAttribute) {
      for (const name of SVG_PRESENTATION) {
        const raw = __ptGetA(el, name);
        if (raw == null) continue;
        const v = String(raw).trim();
        // Голое число в SVG — это пользовательские единицы, то есть пиксели.
        const norm = SVG_LENGTH_ATTRS.has(name) && /^-?[\d.]+$/.test(v) ? v + 'px' : v;
        out.set(name, norm);
      }
    }
    const won = [];
    for (const r of __candidateRules(el)) {
      let ok = false;
      try { ok = matchesSelector(el, r.sel); } catch (e) {}
      if (ok) won.push(r);
    }
    won.sort((a, b) => (a.spec - b.spec) || (a.order - b.order));
    // Сокращения раскладываются здесь, а не при выдаче: на каскад смотрят и
    // раскладка, и использованный кегль, и вычисленный стиль — и каждый из них
    // раньше не видел, что `font: 14px/1.5 Georgia` задаёт `font-size`.
    const take = (n, v) => {
      const pairs = typeof __ptExpand === 'function' ? __ptExpand(n, v) : null;
      if (pairs) { for (const [k, val] of pairs) out.set(k, val); return; }
      out.set(n, v);
    };
    // Собственные свойства (`--*`) и подстановка `var()`. Раньше `var()`
    // доходил до раскладки как есть, и всякая длина, записанная через
    // переменную, не значила ничего — а современные таблицы так пишут почти
    // всё.
    const decls = [];
    const mine = new Map();
    const note = (n, v) => {
      if (n.charCodeAt(0) === 45 && n.charCodeAt(1) === 45) mine.set(n, v);
      else decls.push([n, v]);
    };
    const noteAll = (d) => {
      const raw = __declRaw.get(d);
      if (raw) { const m = raw(); for (const [n, v] of m) note(n, String(__cssPreciseGet(m, n))); return; }
      for (let i = 0; i < d.length; i++) {
        const n = d.item(i);
        note(n, d.getPropertyValue(n));
      }
    };
    for (const r of won) {
      const m = __ruleMap(r);
      if (m) for (const [n, v] of m) note(n, String(v));
    }
    const own = el.style;
    if (own) noteAll(own);
    const vars = __customsFor(el, mine);
    // `inherit` — значение родителя, как оно у него в каскаде; `initial` и
    // `unset` — как будто не писали. Мы брали слово буквально, и
    // `* { box-sizing: inherit }` оставлял всю страницу без `border-box`.
    const parentOf = () => {
      const p = el.parentNode;
      return p && p.nodeType === ELEMENT_NODE ? __cascadeFor(p) : null;
    };
    for (let k = 0; k < decls.length; k++) {
      const v = String(decls[k][1]).trim().toLowerCase();
      if (v === 'initial' || v === 'unset' || v === 'revert' || v === 'revert-layer') { decls[k][1] = null; continue; }
      if (v !== 'inherit') continue;
      const pc = parentOf();
      const got = pc ? pc.get(decls[k][0]) : undefined;
      decls[k][1] = got != null ? got : null;
    }
    for (const [n, v] of decls) {
      if (v == null) { out.delete(n); continue; }
      if (v.indexOf('var(') < 0) { take(n, v); continue; }
      // Не нашедшая значения подстановка делает объявление недействительным:
      // свойство ведёт себя так, будто его не писали.
      const sub = __ptSubstVars(v, vars);
      if (sub != null) take(n, sub);
    }
    __styleCache.set(el, out);
    return out;
  }

  /// Собственные свойства элемента: свои поверх унаследованных. Держатся
  /// цепочкой прототипов, а не копией — у корня их сотни, а узлов тысячи.
  function __customsFor(el, mine) {
    const hit = __passCustom.get(el);
    if (hit) return hit;
    const parent = el.parentNode && el.parentNode.nodeType === ELEMENT_NODE ? el.parentNode
      : (el.parentNode && el.parentNode.host) || null;
    let base = null;
    if (parent) { __cascadeFor(parent); base = __passCustom.get(parent) || null; }
    if (!mine || !mine.size) {
      const same = base || Object.create(null);
      __passCustom.set(el, same);
      return same;
    }
    const out = Object.create(base);
    for (const [n, v] of mine) out[n] = v;
    // Свои значения сами могут ссылаться на переменные — и на свои, и на
    // унаследованные. Круг делает значение недействительным.
    for (const n of mine.keys()) {
      const v = out[n];
      if (typeof v !== 'string' || v.indexOf('var(') < 0) continue;
      const sub = __ptSubstVars(v, out, new Set([n]));
      if (sub == null) out[n] = undefined; else out[n] = sub;
    }
    __passCustom.set(el, out);
    return out;
  }

  /// Подставить `var(--имя[, запас])`. Возвращает null, если подстановка
  /// не удалась и запаса нет.
  function __ptSubstVars(v, vars, busy) {
    let out = '', i = 0, bad = false;
    while (i < v.length) {
      const at = v.indexOf('var(', i);
      if (at < 0) { out += v.slice(i); break; }
      // `var(` внутри имени (`--my-var(`) не бывает, но `somevar(` бывает.
      if (at > 0 && /[\w-]/.test(v[at - 1])) { out += v.slice(i, at + 4); i = at + 4; continue; }
      out += v.slice(i, at);
      let depth = 1, j = at + 4, comma = -1;
      for (; j < v.length && depth; j++) {
        const c = v[j];
        if (c === '(') depth++;
        else if (c === ')') { if (--depth === 0) break; }
        else if (c === ',' && depth === 1 && comma < 0) comma = j;
      }
      const name = v.slice(at + 4, comma < 0 ? j : comma).trim();
      const fallback = comma < 0 ? null : v.slice(comma + 1, j).trim();
      let val = null;
      if (!(busy && busy.has(name))) {
        const raw = vars ? vars[name] : undefined;
        if (typeof raw === 'string') {
          if (raw.indexOf('var(') < 0) val = raw;
          else {
            const b = new Set(busy || []); b.add(name);
            val = __ptSubstVars(raw, vars, b);
          }
        }
      }
      if (val == null && fallback != null) {
        val = fallback.indexOf('var(') < 0 ? fallback : __ptSubstVars(fallback, vars, busy);
      }
      if (val == null) { bad = true; break; }
      out += val;
      i = j + 1;
    }
    return bad ? null : out.trim();
  }

  // Раскладка. Была строчная модель: каждый лист занимал двадцать пикселей, а
  // ширину брал во всё окно, — и любой элемент отвечал одним и тем же размером
  // независимо от своего CSS. Теперь считается обычный блочный поток: отступы,
  // рамки, поля, проценты и `em` от кегля, ширина строки — из метрик гарнитуры.
  // Точность браузера здесь не самоцель, но числа читает сборщик отпечатков, и
  // элемент шириной во всё окно там, где в стиле написано двести пикселей, —
  // это не приблизительность, а противоречие.
  const __BLOCKISH = /^(block|flow-root|list-item|table|flex|grid|table-cell|table-row|table-caption)$/;
  const __INLINEISH = /^(inline|inline-block|inline-flex|inline-grid|inline-table)$/;

  /// Дорожки сетки: `[{px}|{fr}|{auto}]`. Понимает длины, доли, `auto`,
  /// `minmax()`, `repeat()` (и с `auto-fill`/`auto-fit`), имена линий
  /// пропускает. Пусто — одна дорожка `auto`.
  function __gridTracks(raw, avail, gap, fs, rows) {
    const v = raw == null ? 'none' : String(raw).trim();
    if (!v || /^(none|auto|subgrid|masonry)$/i.test(v)) return rows ? [] : [{ auto: true }];
    const split = (t) => {
      const out = []; let depth = 0, cur = '';
      for (const ch of t) {
        if (ch === '(' || ch === '[') depth++;
        if (ch === ')' || ch === ']') depth--;
        if (/\s/.test(ch) && depth === 0) { if (cur) out.push(cur); cur = ''; continue; }
        cur += ch;
      }
      if (cur) out.push(cur);
      return out.filter((x) => x[0] !== '[');
    };
    const one = (t) => {
      const low = t.toLowerCase();
      let m;
      if ((m = /^(-?[\d.]+)fr$/.exec(low))) return { fr: parseFloat(m[1]) };
      if (/^(auto|min-content|max-content)$/.test(low) || /^fit-content\(/.test(low)) return { auto: true };
      if ((m = /^minmax\((.*)\)$/.exec(low))) {
        const [a, b] = __selSplit(m[1]);
        const hi = one(b || 'auto');
        if (hi.fr) return { fr: hi.fr };
        if (hi.px != null) {
          const lo = one(a || '0');
          return { px: lo.px != null ? Math.max(lo.px, hi.px) : hi.px };
        }
        const lo = one(a || 'auto');
        return lo.px != null ? { px: lo.px, grow: true } : { auto: true };
      }
      const px = __lengthPx(t, fs, avail);
      return px != null ? { px } : { auto: true };
    };
    const out = [];
    for (const t of split(v)) {
      const m = /^repeat\(\s*([^,]+?)\s*,(.*)\)$/i.exec(t);
      if (!m) { out.push(one(t)); continue; }
      const list = split(m[2].trim()).map(one);
      let count = parseInt(m[1], 10);
      if (!Number.isFinite(count)) {
        // auto-fill / auto-fit: сколько поместится по наименьшему размеру.
        const size = list.reduce((a, d) => a + (d.px || 0), 0) + gap * list.length;
        count = size > 0 ? Math.max(1, Math.floor((avail + gap) / size)) : 1;
      }
      for (let r = 0; r < Math.min(count, 1000); r++) for (const d of list) out.push(Object.assign({}, d));
    }
    // `minmax(200px, auto)` растёт как `auto`.
    for (const d of out) if (d.grow) { delete d.grow; }
    return out.length ? out : (rows ? [] : [{ auto: true }]);
  }

  /// Кегль корня: от него считается `rem`. Мы брали шестнадцать, а
  /// страницы часто пишут `html { font-size: 62.5% }` и дальше всё в `rem`.
  function __rootFontSize() {
    const doc = globalThis.document;
    const root = doc && doc.documentElement;
    return root ? __usedFontSize(root) : 16;
  }

  /// Одно число с единицей — в пиксели. `base` — от чего проценты; без него
  /// проценты не считаются.
  function __unitPx(x, u, fs, base) {
    switch (u) {
      case 'px': case '': return x;
      case 'em': return x * fs;
      case 'rem': return x * __rootFontSize();
      case 'pt': return x * 4 / 3;
      case 'pc': return x * 16;
      case 'in': return x * 96;
      case 'cm': return x * 96 / 2.54;
      case 'mm': return x * 96 / 25.4;
      case 'q': return x * 96 / 101.6;
      case 'ex': return x * fs / 2;
      case 'ch': return x * fs / 2;
      case '%': return base == null ? null : x / 100 * base;
    }
    // Доли окна, и новые (`dvh`, `svh`, `lvh`) тоже: без панелей и
    // клавиатуры все три равны обычной.
    const m = /^[dsl]?(vh|vw|vmin|vmax|vi|vb)$/.exec(u);
    if (m) {
      const k = m[1];
      const vb = k === 'vh' || k === 'vb' ? LAYOUT.H : k === 'vw' || k === 'vi' ? LAYOUT.W
        : k === 'vmin' ? Math.min(LAYOUT.W, LAYOUT.H) : Math.max(LAYOUT.W, LAYOUT.H);
      return x / 100 * vb;
    }
    return null;
  }

  /// Выражение `calc()`, `min()`, `max()`, `clamp()` — в пиксели, или null.
  /// Раньше любое из них значило «не задано», и блок с
  /// `width: min(100%, 40rem)` растягивался на всё окно.
  function __ptCalcPx(v, fs, base) {
    const toks = [];
    const re = /\s*(?:([+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)([a-z%]*)|([a-z-]+)\(|([()*/,+-]))/iy;
    let pos = 0;
    while (pos < v.length) {
      re.lastIndex = pos;
      const m = re.exec(v);
      if (!m) { if (/^\s*$/.test(v.slice(pos))) break; return null; }
      pos = re.lastIndex;
      if (m[1] != null) {
        // `a -1px` — это вычитание, а не число со знаком, если перед ним
        // стоит операнд.
        const prev = toks[toks.length - 1];
        if (/^[+-]/.test(m[1]) && prev && (prev.t === 'n' || prev.t === ')')) {
          toks.push({ t: m[1][0] });
          toks.push({ t: 'n', x: parseFloat(m[1].slice(1)), u: m[2].toLowerCase() });
        } else toks.push({ t: 'n', x: parseFloat(m[1]), u: m[2].toLowerCase() });
      } else if (m[3] != null) toks.push({ t: 'f', f: m[3].toLowerCase() });
      else toks.push({ t: m[4] });
    }
    let i = 0, fail = false;
    const peek = () => toks[i] || { t: 'end' };
    // Значение — пара: пиксели и признак «голое число», чтобы `2 * 10px`
    // и `10px / 2` считались, а `10px * 10px` — нет.
    const expr = () => {
      let a = term();
      while (!fail && (peek().t === '+' || peek().t === '-')) {
        const op = toks[i++].t, b = term();
        if (fail) break;
        a = { x: op === '+' ? a.x + b.x : a.x - b.x, num: a.num && b.num };
      }
      return a;
    };
    const term = () => {
      let a = factor();
      while (!fail && (peek().t === '*' || peek().t === '/')) {
        const op = toks[i++].t, b = factor();
        if (fail) break;
        if (op === '*') a = { x: a.x * b.x, num: a.num && b.num };
        else { if (!b.num || b.x === 0) { fail = true; break; } a = { x: a.x / b.x, num: a.num }; }
      }
      return a;
    };
    const args = () => {
      const out = [expr()];
      while (!fail && peek().t === ',') { i++; out.push(expr()); }
      if (peek().t !== ')') fail = true; else i++;
      return out;
    };
    const factor = () => {
      const t = toks[i++];
      if (!t) { fail = true; return { x: 0 }; }
      if (t.t === 'n') {
        if (t.u === '') return { x: t.x, num: true };
        const px = __unitPx(t.x, t.u, fs, base);
        if (px == null) fail = true;
        return { x: px || 0, num: false };
      }
      if (t.t === '(') {
        const a = expr();
        if (peek().t !== ')') fail = true; else i++;
        return a;
      }
      if (t.t === '-') { const a = factor(); return { x: -a.x, num: a.num }; }
      if (t.t === 'f') {
        const xs = args();
        if (fail) return { x: 0 };
        const num = xs.every((a) => a.num);
        switch (t.f) {
          case 'calc': case '-webkit-calc':
            if (xs.length !== 1) fail = true;
            return xs[0];
          case 'min': return { x: Math.min(...xs.map((a) => a.x)), num };
          case 'max': return { x: Math.max(...xs.map((a) => a.x)), num };
          case 'clamp':
            if (xs.length !== 3) { fail = true; return { x: 0 }; }
            return { x: Math.max(xs[0].x, Math.min(xs[1].x, xs[2].x)), num };
        }
      }
      fail = true;
      return { x: 0 };
    };
    const r = expr();
    if (fail || i !== toks.length || !isFinite(r.x)) return null;
    return r.x;
  }

  const __CALC_FN = /(?:^|[^\w-])(?:-webkit-)?(?:calc|min|max|clamp)\(/i;

  function __lengthPx(raw, fs, base) {
    if (raw == null) return null;
    const v = String(raw).trim();
    let m;
    if ((m = /^(-?(?:\d+\.?\d*|\.\d+))([a-z%]*)$/i.exec(v))) {
      const u = m[2].toLowerCase();
      const px = __unitPx(parseFloat(m[1]), u, fs, base);
      if (px == null) return null;
      // Доли окна и проценты браузер держит с точностью в 1/64 пикселя.
      return u === '%' || /v/.test(u) ? Math.round(px * 64) / 64 : px;
    }
    if (__CALC_FN.test(v)) {
      const px = __ptCalcPx(v, fs, base);
      return px == null ? null : Math.round(px * 64) / 64;
    }
    return null;
  }

  // Высота строки при `line-height: normal` и подъём до базовой линии — из
  // самой гарнитуры, а не из доли кегля: у Liberation Sans строка это 1,15
  // кегля, у другой гарнитуры своё.
  function __fontBox(fs, family) {
    if (typeof __pt_canvasMeasureText === 'function') {
      try {
        const m = __pt_canvasMeasureText('', fs, family || 'sans-serif', false, false);
        return { line: Math.round(m[7] || fs * 1.15), asc: m[5] || Math.round(fs * 0.9), desc: m[6] || Math.round(fs * 0.2) };
      } catch (e) {}
    }
    return { line: Math.round(fs * 1.15), asc: Math.round(fs * 0.9), desc: Math.round(fs * 0.2) };
  }
  const __normalLine = (fs, family) => __fontBox(fs, family).line;

  // Мерить строку дорого: раскладка HarfBuzz'ом с подбором шрифта по знакам.
  // А раскладка страницы меряет одно и то же снова и снова — каждая правка
  // дерева пересчитывает все коробки, и пять сотен узлов дают пять сотен
  // замеров тех же слов. Ответ зависит только от строки и шрифта, поэтому
  // держим его при себе; при переполнении — начинаем сначала, чтобы карта
  // не росла на странице, которая печатает уникальный текст.
  const __widths = new Map();
  // Пробелы в SVG схлопываются: перевод строки выброшен, табуляция — пробел,
  // подряд идущие сжаты в один, по краям срезаны. `<text>  ii  </text>` меряется
  // как «ii», а не как строка с отступами.
  const __svgText = (el) => String((el && el.textContent) || '')
    .replace(/[\r\n]/g, '').replace(/\t/g, ' ').replace(/ +/g, ' ').trim();

  function __textMetrics(text, fs, family, bold, italic) {
    const t = String(text);
    const key = fs + '|' + (family || 'sans-serif') + '|' + (bold ? 1 : 0) + (italic ? 1 : 0) + '|' + t;
    const hit = __widths.get(key);
    if (hit !== undefined) return hit;
    let m = null;
    if (typeof __pt_canvasMeasureText === 'function') {
      try { m = __pt_canvasMeasureText(t, fs, family || 'sans-serif', !!bold, !!italic); }
      catch (e) {}
    }
    if (!m) m = [t.length * fs * 0.5, 0, t.length * fs * 0.5, fs * 0.9, fs * 0.2, fs * 0.9, fs * 0.2, fs * 1.15];
    if (__widths.size > 20000) __widths.clear();
    __widths.set(key, m);
    return m;
  }

  function __textWidth(text, fs, family, bold, italic) {
    return __textMetrics(text, fs, family, bold, italic)[0] || 0;
  }

  // Перенос по словам. Абзац в браузере занимает столько строк, сколько
  // требует его ширина, а у нас любой текст умещался в одну — и абзац шириной
  // сто двадцать пикселей отвечал высотой восемнадцать вместо семидесяти двух.
  // Разрыв жадный, по пробелам, хвостовой пробел в ширину строки не входит —
  // как в браузере.
  function __wrapLines(text, maxWidth, fs, family, bold) {
    const words = String(text).split(' ').filter((w) => w.length);
    const out = [];
    if (!words.length) return out;
    if (!(maxWidth > 0)) {
      const all = words.join(' ');
      return [{ text: all, width: Math.round(__textWidth(all, fs, family, bold, false) * 64) / 64 }];
    }
    let line = '';
    for (const w of words) {
      const next = line ? line + ' ' + w : w;
      const width = __textWidth(next, fs, family, bold, false);
      if (line && width > maxWidth) {
        out.push({ text: line, width: __textWidth(line, fs, family, bold, false) });
        line = w;
      } else {
        line = next;
      }
    }
    if (line) out.push({ text: line, width: __textWidth(line, fs, family, bold, false) });
    // Ширины строк браузер, как и всё остальное, держит в шестьдесят четвёртых.
    for (const l of out) l.width = Math.round(l.width * 64) / 64;
    return out;
  }

  const __OWN_TEXT = (el) => {
    let t = '';
    for (const c of (el.__ptKids || [])) if (c.nodeType === TEXT_NODE) t += c.data || '';
    return t.replace(/\s+/g, ' ').trim();
  };

  // Размеры, которые элементам даёт сам движок браузера, а не страница. Сняты
  // с Chrome 151: флажок 13×13, поле ввода 177×15 в рамке 2 и отступе 2/1,
  // кнопка сжимается по надписи с отступом 6/1. У полей формы свой кегль —
  // 13,3333 пикселя, — и без него надписи на кнопках меряются не тем.
  const UA_FORM_FONT = 13.3333;
  function __uaBox(el, tag) {
    if (tag === 'input') {
      const t = String((el.getAttribute && __ptGetA(el, 'type')) || 'text').toLowerCase();
      if (t === 'checkbox') return { w: 13, h: 13, p: [0, 0], b: 0, m: [3, 3] };
      if (t === 'radio') return { w: 13, h: 13, p: [0, 0], b: 0, m: [3, 3] };
      if (t === 'range') return { w: 129, h: 16, p: [0, 0], b: 0, m: [2, 2] };
      if (t === 'file') return { w: 253, h: 21, p: [0, 0], b: 0, m: [0, 0] };
      if (t === 'submit' || t === 'button' || t === 'reset') {
        // Ненадписанная кнопка отправки подписана движком, а не страницей.
        const dflt = t === 'submit' ? 'Submit' : t === 'reset' ? 'Reset' : '';
        return { label: true, dflt, h: 15, p: [1, 6], b: 2, m: [0, 0] };
      }
      if (t === 'hidden') return null;
      return { w: 177, h: 15, p: [1, 2], b: 2, m: [0, 0] };
    }
    if (tag === 'button') return { label: true, h: 15, p: [1, 6], b: 2, m: [0, 0] };
    // У списка размер задан по внешней рамке, а не по содержимому.
    if (tag === 'select') return { w: 28, h: 17, p: [0, 0], b: 1, m: [0, 0] };
    if (tag === 'textarea') return { w: 195, h: 36, p: [2, 2], b: 1, m: [0, 0] };
    if (tag === 'iframe') return { w: 300, h: 150, p: [0, 0], b: 2, m: [0, 0] };
    if (tag === 'img' || tag === 'canvas' || tag === 'video') return { w: 0, h: 0, p: [0, 0], b: 0, m: [0, 0] };
    return null;
  }

  // Поля, которые блочным элементам даёт таблица стилей самого браузера. Без
  // них абзацы и заголовки лежат вплотную, и вся страница ниже съезжает вверх.
  // Первое число — поле сверху и снизу в долях кегля, второе — по бокам в
  // пикселях. В долях, а не в пикселях: у заголовка поле считается от его
  // собственного кегля, и `h1` внутри блока с другим шрифтом отступает иначе.
  const UA_MARGIN = {
    p: [1, 0], blockquote: [1, 40], figure: [1, 40], ul: [1, 0], ol: [1, 0],
    dir: [1, 0], menu: [1, 0], dl: [1, 0], dd: [0, 40], pre: [1, 0], form: [0, 0],
    h1: [0.67, 0], h2: [0.83, 0], h3: [1, 0], h4: [1.33, 0], h5: [1.67, 0], h6: [2.33, 0],
  };
  // Поля, заданные прямо в пикселях: у тела страницы это восемь пикселей со
  // всех сторон, и без них вся раскладка стоит на восемь пикселей выше
  // браузерной.
  const UA_MARGIN_PX = { body: [8, 8], hr: [8, 0], fieldset: [0, 2] };

  function __uaMargin(tag, fs) {
    const px = UA_MARGIN_PX[tag];
    if (px) return px;
    const em = UA_MARGIN[tag];
    return em ? [em[0] * (fs || 16), em[1]] : null;
  }

  // Направление письма по таблице браузера. Начальное значение —
  // `normal`, а `isolate` браузер раздаёт блочным элементам списком, и в этот
  // список не входят ни тело страницы, ни поля ввода. Мы отвечали `isolate`
  // всему, что не строчное, и перечисленный стиль расходился.
  const UA_BIDI = {
    html: 'normal', body: 'normal', input: 'normal', button: 'normal', select: 'normal',
    textarea: 'normal', fieldset: 'normal', option: 'normal', optgroup: 'normal',
    meter: 'normal', progress: 'normal', details: 'normal', template: 'normal',
    output: 'isolate',
  };

  // Кегль и насыщенность от таблицы браузера. Заголовок крупнее родителя в
  // свою долю, `small` мельче в 1,2 раза, и всё это множится по цепочке —
  // `small` внутри `small` мельче вдвойне, как в браузере.
  const UA_FONT_SIZE = {
    h1: 2, h2: 1.5, h3: 1.17, h4: 1, h5: 0.83, h6: 0.67,
    small: 1 / 1.2, sub: 1 / 1.2, sup: 1 / 1.2, big: 1.2,
  };
  const UA_BOLD = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'b', 'strong', 'th']);

  // Что браузер набирает моноширинным: свой кегль (13 пикселей против
  // шестнадцати) и своё семейство. Поле области ввода — 13⅓, как у прочих
  // полей.
  const UA_MONO = new Set(['pre', 'code', 'kbd', 'samp', 'tt', 'textarea', 'xmp', 'plaintext', 'listing']);

  // Строчный ли это уровень: такие дети ложатся в одну строку, а не столбиком.
  /// Два поля, схлопнутые в одно: наибольшее положительное плюс наименьшее
  /// отрицательное.
  const __collapseM = (a, b) => Math.max(0, a, b) + Math.min(0, a, b);

  /// Ширина по содержимому (max-content), рамка включительно: сколько
  /// займёт элемент, если ему ничего не навязывать. Нужна ребёнку гибкого
  /// ряда: его основа — эта ширина, а не вся строка. Мы давали всю строку,
  /// и пустой `div`, который api.js Turnstile вставляет в центрованный ряд,
  /// у нас стоял у правого края — а его место уходит виджету в письме.
  function __maxContentW(el, depth) {
    depth = depth || 0;
    if (depth > 40 || !el || el.nodeType !== ELEMENT_NODE || __isUnboxed(el)) return 0;
    const cs = __cascadeFor(el);
    const fs = __usedFontSize(el);
    const tag = (el.localName || '').toLowerCase();
    const len = (n) => __lengthPx(cs.get(n), fs, null);
    const bbox = /^border-box$/i.test(String(cs.get('box-sizing') || '').trim());
    const pad = (len('padding-left') || 0) + (len('padding-right') || 0)
      + (len('border-left-width') || 0) + (len('border-right-width') || 0);
    const clamp = (w) => {
      const hi = len('max-width'), lo = len('min-width');
      if (hi != null && w > (bbox ? hi : hi + pad)) w = bbox ? hi : hi + pad;
      if (lo != null && w < (bbox ? lo : lo + pad)) w = bbox ? lo : lo + pad;
      return w;
    };
    const w = len('width');
    if (w != null) return clamp(bbox ? w : w + pad);
    const ua = __uaBox(el, tag);
    if (ua && ua.w != null) return clamp(ua.w + pad);
    let familyRaw = cs.get('font-family');
    if (familyRaw == null) familyRaw = __inheritedValue(el, 'font-family');
    const family = String(familyRaw || '').trim() || 'sans-serif';
    const weight = cs.get('font-weight') || __inheritedValue(el, 'font-weight') || (UA_BOLD.has(tag) ? '700' : '');
    const bold = /(^|\s)(bold|[5-9]00)(\s|$)/i.test(String(weight));
    const text = __OWN_TEXT(el);
    let inner = text ? __textWidth(text, fs, family, bold, false) : 0;
    const kids = [];
    for (const c of (el.__ptKids || [])) {
      if (c.nodeType !== ELEMENT_NODE || __isUnboxed(c)) continue;
      const p = String(__cascadeFor(c).get('position') || 'static').toLowerCase();
      if (p !== 'absolute' && p !== 'fixed') kids.push(c);
    }
    const display = String(cs.get('display') || CS_DISPLAY[tag] || 'block').toLowerCase();
    const outer = (c) => {
      const ccs = __cascadeFor(c), cfs = __usedFontSize(c);
      return __maxContentW(c, depth + 1) + (__lengthPx(ccs.get('margin-left'), cfs, null) || 0)
        + (__lengthPx(ccs.get('margin-right'), cfs, null) || 0);
    };
    const gap = (n) => { const v = cs.get(n); return v == null || /normal/i.test(String(v)) ? 0 : (__lengthPx(v, fs, null) || 0); };
    if (/flex$/.test(display) && !/^column/.test(String(cs.get('flex-direction') || 'row'))) {
      inner += kids.reduce((a, c) => a + outer(c), 0) + gap('column-gap') * Math.max(0, kids.length - 1);
    } else if (/grid$/.test(display)) {
      const n = Math.max(1, __gridTracks(cs.get('grid-template-columns'), 0, 0, fs).length);
      const cols = new Array(n).fill(0);
      kids.forEach((c, i) => { cols[i % n] = Math.max(cols[i % n], outer(c)); });
      inner += cols.reduce((a, x) => a + x, 0) + gap('column-gap') * (n - 1);
    } else {
      // Строчные — в одну строку, блочные — каждый своей.
      let line = inner, widest = 0;
      for (const c of kids) {
        if (__isInlineLevel(c)) line += outer(c);
        else { widest = Math.max(widest, line, outer(c)); line = 0; }
      }
      inner = Math.max(widest, line);
    }
    return clamp(inner + pad);
  }

  function __isInlineLevel(el) {
    const tag = (el.localName || '').toLowerCase();
    const d = String(__cascadeFor(el).get('display') || CS_DISPLAY[tag] || 'block').toLowerCase();
    return /^inline(-block|-flex|-grid|-table)?$/.test(d);
  }

  // Атомарный ли он — прямоугольник, который стоит в строке целиком:
  // `inline-block`, картинка, поле ввода. Обычный `<span>` таким не считается:
  // он разливается по строке и высоту берёт от своего шрифта.
  const __ATOMIC_TAGS = new Set(['img', 'input', 'button', 'select', 'textarea', 'svg',
    'canvas', 'video', 'audio', 'object', 'embed', 'iframe', 'meter', 'progress']);
  function __isAtomicInline(el) {
    const tag = (el.localName || '').toLowerCase();
    const d = String(__cascadeFor(el).get('display') || CS_DISPLAY[tag] || 'block').toLowerCase();
    return d !== 'inline' || __ATOMIC_TAGS.has(tag);
  }

  // Прогон строчных детей: слева направо, с переносом по ширине и
  // выравниванием по базовой линии. Атомарный ребёнок стоит на базовой линии
  // нижним краем — так браузер ставит `inline-block`.
  function __layoutInlineRun(run, originX, originY, availW, strut, strutLine) {
    const q = (v) => Math.floor(v * 64) / 64;
    const sAsc = strut ? strut.asc : strutLine * 0.8;
    const sDesc = Math.max(0, strutLine - sAsc);
    let y = originY, widest = 0;
    let line = [];
    let lineW = 0;
    const flush = () => {
      if (!line.length) return;
      // Пустые строчные коробки строки не делают: у браузера `<span></span>`
      // не даёт ни высоты, ни строки.
      const solid = line.some((it) => it.atomic || it.text);
      let asc = solid ? sAsc : 0, desc = solid ? sDesc : 0;
      for (const it of line) {
        const over = it.atomic ? it.box.h + it.mt + it.mb : (it.box.asc || sAsc);
        const under = it.atomic ? 0 : Math.max(0, (it.box.h || 0) - (it.box.asc || sAsc));
        asc = Math.max(asc, over);
        desc = Math.max(desc, under);
      }
      const height = solid ? asc + desc : 0;
      for (const it of line) {
        const top = it.atomic ? y + asc - it.box.h - it.mb : y + asc - (it.box.asc || sAsc);
        __ptShiftBox(it.el, it.x, q(top));
        widest = Math.max(widest, it.x + it.box.w + it.mr - originX);
      }
      y = q(y + height);
      line = [];
      lineW = 0;
    };
    for (const el of run) {
      const box = __layoutOne(el, originX, y, availW, strut);
      if (!box) continue;
      const cs = __cascadeFor(el);
      const cfs = __usedFontSize(el);
      const m = (name) => __lengthPx(cs.get(name), cfs, availW) || 0;
      const kids = (el.__ptKids || []).filter((k) => k.nodeType === ELEMENT_NODE);
      const it = {
        el, box, atomic: __isAtomicInline(el),
        text: !!String(__OWN_TEXT(el) || '').trim() || kids.length > 0,
        ml: m('margin-left'), mr: m('margin-right'), mt: m('margin-top'), mb: m('margin-bottom'),
        x: 0,
      };
      const outer = box.w + it.ml + it.mr;
      if (line.length && lineW + outer > availW + 0.5) flush();
      it.x = q(originX + lineW + it.ml);
      lineW += outer;
      line.push(it);
    }
    flush();
    return { y, widest };
  }

  // Переставить уже разложенную коробку вместе со всем, что внутри.
  function __ptShiftBox(el, x, y) {
    const b = el.__ptBox;
    if (!b) return;
    const dx = x - b.x, dy = y - b.y;
    if (!dx && !dy) return;
    const walk = (node) => {
      const nb = node.__ptBox;
      if (nb) {
        nb.x += dx; nb.y += dy;
        nb.cx += dx; nb.cy += dy;
        if (nb.lineTop != null) nb.lineTop += dy;
      }
      for (const k of (node.__ptKids || [])) if (k.nodeType === ELEMENT_NODE) walk(k);
      if (node.__ptShadow) {
        for (const k of (node.__ptShadow.__ptKids || [])) if (k.nodeType === ELEMENT_NODE) walk(k);
      }
    };
    walk(el);
  }

  function __layoutOne(el, originX, originY, availW, strut, forced) {
    // В порядке документа, не после детей: попадание в точку ищется с конца
    // списка, и глубокий элемент должен стоять там позже своего родителя.
    __boxes.push(el);
    const cs = __cascadeFor(el);
    const fs = __usedFontSize(el);
    const tag = (el.localName || '').toLowerCase();
    // Шрифт наследуется: у `<span>` внутри тела своего объявления нет, и без
    // наследования он мерился запасной гарнитурой — а с ней не сходится ни
    // ширина слова, ни высота строки.
    let familyRaw = cs.get('font-family');
    if (familyRaw == null) familyRaw = cs.get('font');
    if (familyRaw == null && typeof __inheritedValue === 'function') {
      familyRaw = __inheritedValue(el, 'font-family');
    }
    const family = String(familyRaw || '').trim() || 'sans-serif';
    let weight = cs.get('font-weight') || cs.get('font');
    // Таблица браузера сильнее наследования: `<b>` внутри обычного текста
    // жирный, даже если у родителя насыщенность задана.
    if (weight == null && UA_BOLD.has(tag)) weight = '700';
    if (weight == null && typeof __inheritedValue === 'function') {
      weight = __inheritedValue(el, 'font-weight');
    }
    const bold = /(^|\s)(bold|[5-9]00)(\s|$)/i.test(String(weight || ''));
    const len = (name, base) => __lengthPx(cs.get(name), fs, base);
    const side = (prefix, suffix) => {
      const all = cs.get(prefix);
      const one = ['top', 'right', 'bottom', 'left'].map((k) => len(prefix + '-' + k, availW));
      if (all != null) {
        const parts = String(all).trim().split(/\s+/);
        const pick = (i) => parts[[0, 1, 2, 3].map((k) => Math.min(k, parts.length - 1))[i]];
        ['top', 'right', 'bottom', 'left'].forEach((k, i) => {
          if (one[i] == null) one[i] = __lengthPx(pick(i), fs, availW);
        });
      }
      return one;
    };
    const rawM = side('margin');
    // Ноль от автора — это заданное значение, а не молчание: страница с
    // `body { margin: 0 }` не должна получать браузерные восемь пикселей.
    const setM = rawM.map((v) => v != null);
    let [mt, mr, mb, ml] = rawM.map((v) => v || 0);
    let [pt_, pr, pb, pl] = side('padding').map((v) => v || 0);
    let [bt, br, bb, bl] = ['top', 'right', 'bottom', 'left']
      .map((k) => len('border-' + k + '-width', availW) || 0);
    const borderAll = cs.get('border') || cs.get('border-width');
    if (borderAll != null && !bt && !br && !bb && !bl) {
      const m = /(-?[\d.]+)px/.exec(String(borderAll));
      const w = m && !/\bnone\b/.test(String(borderAll)) ? parseFloat(m[1]) : 0;
      bt = br = bb = bl = w;
    }
    const display = String(cs.get('display') || CS_DISPLAY[tag] || 'block').toLowerCase();
    const ovAll = String(cs.get('overflow') || '').toLowerCase();
    const ovX = String(cs.get('overflow-x') || ovAll || 'visible').toLowerCase();
    const ovY = String(cs.get('overflow-y') || ovAll || 'visible').toLowerCase();
    // Ребёнок гибкого контейнера — блок, каким бы ни был его собственный
    // `display`: браузер его «блокирует», и высота у него строки, а не чернил.
    const forcedW = !!(forced && forced.w != null);
    const inlineish = __INLINEISH.test(display) && !(forced && forced.block);
    const position = String(cs.get('position') || 'static').toLowerCase();

    const uam = __uaMargin(tag, fs);
    if (uam) {
      if (!setM[0] && !setM[2]) { mt = uam[0]; mb = uam[0]; }
      if (!setM[3] && !setM[1]) { ml = uam[1]; mr = uam[1]; }
    }
    const ua = __uaBox(el, tag);
    if (ua) {
      if (!pt_ && !pb && ua.p) { pt_ = ua.p[0]; pb = ua.p[0]; }
      if (!pl && !pr && ua.p) { pl = ua.p[1]; pr = ua.p[1]; }
      if (!bt && !br && !bb && !bl && ua.b) { bt = br = bb = bl = ua.b; }
      if (!setM[0] && !setM[2] && ua.m) { mt = ua.m[0]; mb = ua.m[0]; }
      if (!setM[3] && !setM[1] && ua.m) { ml = ua.m[1]; mr = ua.m[1]; }
    }
    // `box-sizing: border-box` — размер назван вместе с полями и рамкой. Мы
    // его не знали, и почти любая современная страница (`* { box-sizing:
    // border-box }`) выходила у нас шире и выше, чем у браузера.
    const bbox = /^border-box$/i.test(String(cs.get('box-sizing') || '').trim());
    const inW = (v) => (v == null ? null : bbox ? Math.max(0, v - pl - pr - bl - br) : v);
    const inH = (v) => (v == null ? null : bbox ? Math.max(0, v - pt_ - pb - bt - bb) : v);
    // Проценты высоты — от заданной высоты родителя; у корня это окно. Мы
    // считали их от ширины, и `height: 100%` давало высоту в ширину окна.
    const up = el.parentNode;
    const baseH = up && up.nodeType === ELEMENT_NODE
      ? (up.__ptDefH != null ? up.__ptDefH : null) : LAYOUT.H;
    const explicitW = inW(len('width', availW));
    const explicitH = inH(len('height', baseH));
    el.__ptDefH = explicitH;
    const frame = tag === 'iframe' || tag === 'img' || tag === 'canvas' || tag === 'video';
    const attrW = frame && el.getAttribute ? __lengthPx(__ptGetA(el, 'width'), fs, availW) : null;
    const attrH = frame && el.getAttribute ? __lengthPx(__ptGetA(el, 'height'), fs, availW) : null;

    let cw = explicitW != null ? explicitW : attrW;
    if (cw == null && ua) {
      cw = ua.label
        ? __textWidth((el.getAttribute && __ptGetA(el, 'value')) || __OWN_TEXT(el) || ua.dflt || '',
                      fs, family, bold, false)
        : ua.w;
    }
    if (cw == null && !inlineish) cw = Math.max(0, availW - ml - mr - bl - br - pl - pr);
    // Пределы ширины: без них колонка с `max-width` растягивалась во всё
    // окно, а вместе с ней уезжала и вся геометрия под ней.
    if (cw != null) {
      const maxW = inW(len('max-width', availW));
      const minW = inW(len('min-width', availW));
      if (maxW != null && cw > maxW) cw = maxW;
      if (minW != null && cw < minW) cw = minW;
    }
    // `margin: 0 auto` — блок посередине. Мы клали его влево, и всякая
    // страница с колонкой по центру отдавала не ту геометрию: челлендж
    // спрашивает прямоугольники у полутора десятков узлов.
    const autoSide = (name) => {
      const v = cs.get(name);
      if (v != null) return /^auto$/i.test(String(v).trim());
      const all = cs.get('margin');
      if (all == null) return false;
      const parts = String(all).trim().split(/\s+/);
      const i = name === 'margin-left' ? 3 : 1;
      return /^auto$/i.test(parts[[0, 1, 2, 3].map((k) => Math.min(k, parts.length - 1))[i]] || '');
    };
    if (!inlineish && cw != null && (autoSide('margin-left') || autoSide('margin-right'))) {
      const free = Math.max(0, availW - cw - bl - br - pl - pr);
      const left = autoSide('margin-left'), right = autoSide('margin-right');
      if (left && right) { ml = free / 2; mr = free / 2; }
      else if (left) ml = free - mr;
      else mr = free - ml;
    }
    // Гибкий родитель назначает ребёнку длину сам — и до того, как тот
    // разложит своё содержимое, иначе строки обернутся не по той ширине.
    if (forced && forced.w != null) cw = Math.max(0, forced.w - pl - pr - bl - br);

    let boxX = originX + ml, boxY = originY + mt;
    if (position === 'absolute' || position === 'fixed') {
      const left = len('left', availW), top = len('top', availW);
      if (left != null) boxX = left;
      if (top != null) boxY = top;
    }

    const kids = [];
    if (el.__ptShadow) for (const c of el.__ptShadow.__ptKids) kids.push(c);
    for (const c of (el.__ptKids || [])) kids.push(c);
    const boxedKids = kids.filter((c) => c.nodeType === ELEMENT_NODE && !__isUnboxed(c));

    // Строчный элемент сжимается по содержимому: по детям, а если их нет — по
    // собственному тексту, измеренному настоящей гарнитурой.
    if (cw == null) {
      cw = boxedKids.length ? 0 : __textWidth(__OWN_TEXT(el), fs, family, bold, false);
    }
    if (forcedW) cw = Math.max(0, forced.w - pl - pr - bl - br);

    const fbox = __fontBox(fs, family);
    // Высота строки — из стиля, а не из метрик гарнитуры: `font: 16px/1.4`
    // делает строку в 22,4 пикселя, и ребёнок гибкого контейнера ровно
    // такой высоты. Мы брали высоту чернил и отвечали восемнадцатью.
    let lineH = fbox.line;
    {
      let lh = cs.get('line-height');
      if (lh == null && typeof __inheritedValue === 'function') lh = __inheritedValue(el, 'line-height');
      const t = lh == null ? '' : String(lh).trim();
      if (t && t !== 'normal') {
        lineH = /^[\d.]+$/.test(t) ? parseFloat(t) * fs : (__lengthPx(t, fs, availW) || fbox.line);
      }
    }
    const contentX = boxX + bl + pl;
    let contentY = boxY + bt + pt_;
    // Поля детей, убежавшие наружу через пустой край родителя.
    let escapedTop = 0, escapedBottom = 0, hasEscapedTop = false;
    let y = contentY, widest = 0, deepest = 0;
    // Гибкий контейнер: дети ложатся в ряд (или в столбец), свободное место
    // делится по `flex-grow`, нехватка — по `flex-shrink`, а поперёк они по
    // умолчанию растягиваются. Раньше мы клали их обычным блочным потоком, и
    // виджет — а он почти всегда гибкий — получал не ту геометрию.
    const flexish = display === 'flex' || display === 'inline-flex';
    // Сетка: дети по ячейкам, строки высотой в самого высокого, промежутки
    // `gap`, растяжение по ячейке. Раньше сетка раскладывалась обычным
    // блочным потоком — без промежутков и без растяжения, и форма входа
    // chess.com (сетка с `gap: 16px`) выходила на полсотни пикселей ниже.
    const gridish = display === 'grid' || display === 'inline-grid';
    if (gridish && boxedKids.length) {
      const gapLen = (n) => {
        const v = cs.get(n);
        if (v == null || /^normal$/i.test(String(v).trim())) return 0;
        return __lengthPx(v, fs, cw) || 0;
      };
      const colGap = gapLen('column-gap'), rowGap = gapLen('row-gap');
      const flow = boxedKids.filter((c) => {
        const p = String(__cascadeFor(c).get('position') || 'static').toLowerCase();
        return p !== 'absolute' && p !== 'fixed';
      });
      const cols = __gridTracks(cs.get('grid-template-columns'), cw, colGap, fs);
      const n = cols.length;
      const marg = (c, a, b) => {
        const ccs = __cascadeFor(c), cfs = __usedFontSize(c);
        return (__lengthPx(ccs.get(a), cfs, cw) || 0) + (__lengthPx(ccs.get(b), cfs, cw) || 0);
      };
      // Ширины колонок: заданные — как есть, доли — от остатка, `auto` —
      // по содержимому, а остаток без долей делится между `auto` поровну.
      const widths = cols.map((t) => (t.px != null ? t.px : 0));
      const frTotal = cols.reduce((a, t) => a + (t.fr || 0), 0);
      const autos = [];
      cols.forEach((t, k) => { if (t.auto) autos.push(k); });
      if (autos.length && frTotal) {
        flow.forEach((c, i) => {
          const k = i % n;
          if (!cols[k].auto) return;
          const b = __layoutOne(c, contentX, contentY, cw, fbox) || { w: 0 };
          widths[k] = Math.max(widths[k], b.w + marg(c, 'margin-left', 'margin-right'));
        });
      }
      const usedW = widths.reduce((a, w) => a + w, 0) + colGap * Math.max(0, n - 1);
      let freeW = Math.max(0, cw - usedW);
      if (frTotal) cols.forEach((t, k) => { if (t.fr) widths[k] = freeW * t.fr / frTotal; });
      else if (autos.length) { for (const k of autos) widths[k] += freeW / autos.length; freeW = 0; }
      const totalW = widths.reduce((a, w) => a + w, 0) + colGap * Math.max(0, n - 1);
      const jc = String(cs.get('justify-content') || 'normal').toLowerCase();
      const slackW = Math.max(0, cw - totalW);
      const leadX = jc === 'center' ? slackW / 2 : (jc === 'end' || jc === 'flex-end' || jc === 'right') ? slackW : 0;
      const colX = [];
      { let x = contentX + leadX; for (let k = 0; k < n; k++) { colX.push(x); x += widths[k] + colGap; } }
      const rowsT = __gridTracks(cs.get('grid-template-rows'), explicitH != null ? explicitH : 0, rowGap, fs, true);
      const ji = String(cs.get('justify-items') || 'normal').toLowerCase();
      const ai = String(cs.get('align-items') || 'normal').toLowerCase();
      const selfOf = (c, prop, dflt) => {
        const v = String(__cascadeFor(c).get(prop) || 'auto').toLowerCase();
        return v === 'auto' ? dflt : v;
      };
      const stretchy = (v) => v === 'normal' || v === 'stretch' || v === 'legacy';
      // Первый проход — высоты строк.
      const nRows = Math.ceil(flow.length / n);
      const rowH = new Array(nRows).fill(0);
      flow.forEach((c, i) => {
        const k = i % n, r = (i / n) | 0;
        const ccs = __cascadeFor(c);
        const js = selfOf(c, 'justify-self', ji);
        const fixedW = ccs.get('width') != null && !/^auto$/i.test(String(ccs.get('width')).trim());
        const mx = marg(c, 'margin-left', 'margin-right');
        const b = __layoutOne(c, colX[k], contentY, widths[k], fbox,
          stretchy(js) && !fixedW ? { w: Math.max(0, widths[k] - mx), block: true } : { block: true }) || { h: 0 };
        rowH[r] = Math.max(rowH[r], b.h + marg(c, 'margin-top', 'margin-bottom'));
      });
      for (let r = 0; r < nRows; r++) {
        const t = rowsT[r];
        if (t && t.px != null) rowH[r] = t.px;
      }
      const totalH = rowH.reduce((a, h) => a + h, 0) + rowGap * Math.max(0, nRows - 1);
      const ac = String(cs.get('align-content') || 'normal').toLowerCase();
      const boxH = explicitH != null ? explicitH : null;
      const slackH = boxH != null ? Math.max(0, boxH - totalH) : 0;
      const leadY = ac === 'center' ? slackH / 2 : (ac === 'end' || ac === 'flex-end') ? slackH : 0;
      // Второй проход — окончательные места.
      const rowY = [];
      { let yy = contentY + leadY; for (let r = 0; r < nRows; r++) { rowY.push(yy); yy += rowH[r] + rowGap; } }
      flow.forEach((c, i) => {
        const k = i % n, r = (i / n) | 0;
        const ccs = __cascadeFor(c);
        const js = selfOf(c, 'justify-self', ji), as = selfOf(c, 'align-self', ai);
        const fixedW = ccs.get('width') != null && !/^auto$/i.test(String(ccs.get('width')).trim());
        const fixedH = ccs.get('height') != null && !/^auto$/i.test(String(ccs.get('height')).trim());
        const mx = marg(c, 'margin-left', 'margin-right'), my = marg(c, 'margin-top', 'margin-bottom');
        const sw = stretchy(js) && !fixedW, sh = stretchy(as) && !fixedH;
        let x = colX[k], yy = rowY[r];
        if (!sw || !sh) {
          const probe = __layoutOne(c, x, yy, widths[k], fbox,
            { w: sw ? Math.max(0, widths[k] - mx) : null, h: null, block: true }) || { w: 0, h: 0 };
          if (!sw) {
            const free = widths[k] - probe.w - mx;
            if (js === 'center') x += free / 2;
            else if (js === 'end' || js === 'flex-end' || js === 'right' || js === 'self-end') x += free;
          }
          if (!sh) {
            const free = rowH[r] - probe.h - my;
            if (as === 'center') yy += free / 2;
            else if (as === 'end' || as === 'flex-end' || as === 'self-end') yy += free;
          }
        }
        const cb = __layoutOne(c, x, yy, widths[k], fbox, {
          w: sw ? Math.max(0, widths[k] - mx) : null,
          h: sh ? Math.max(0, rowH[r] - my) : null,
          block: true,
        });
        if (cb) {
          widest = Math.max(widest, cb.x - contentX + cb.w);
          deepest = Math.max(deepest, cb.y - contentY + cb.h);
        }
      });
      y = contentY + Math.max(totalH, 0);
      if (inlineish && !forcedW && explicitW == null) cw = Math.min(cw || totalW, totalW) || totalW;
      for (const c of boxedKids) {
        const p = String(__cascadeFor(c).get('position') || 'static').toLowerCase();
        if (p === 'absolute' || p === 'fixed') __layoutOne(c, contentX, contentY, cw, fbox);
      }
    } else if (flexish && boxedKids.length) {
      const dir = String(cs.get('flex-direction') || 'row').toLowerCase();
      const row = dir.lastIndexOf('column', 0) !== 0;
      const reverse = /-reverse$/.test(dir);
      const gapMain = len(row ? 'column-gap' : 'row-gap', cw) || 0;
      const align = String(cs.get('align-items') || 'normal').toLowerCase();
      const justify = String(cs.get('justify-content') || 'normal').toLowerCase();
      const flow = boxedKids.filter((c) => {
        const p = String(__cascadeFor(c).get('position') || 'static').toLowerCase();
        return p !== 'absolute' && p !== 'fixed';
      });
      // Первый проход — узнать естественные размеры.
      const items = flow.map((c) => {
        const ccs = __cascadeFor(c);
        const cb = __layoutOne(c, contentX, contentY, cw, fbox) || { w: 0, h: 0 };
        const cfs = __usedFontSize(c);
        const mw = (__lengthPx(ccs.get('margin-left'), cfs, cw) || 0)
                 + (__lengthPx(ccs.get('margin-right'), cfs, cw) || 0);
        const mh = (__lengthPx(ccs.get('margin-top'), cfs, cw) || 0)
                 + (__lengthPx(ccs.get('margin-bottom'), cfs, cw) || 0);
        const num = (v, dflt) => { const n = parseFloat(v); return Number.isFinite(n) ? n : dflt; };
        const basis = String(ccs.get('flex-basis') || 'auto').toLowerCase();
        const basisPx = basis === 'auto' || basis === 'content'
          ? null : __lengthPx(basis, cfs, cw);
        // Основа в ряду — ширина по содержимому, если ширина не задана.
        const autoW = ccs.get('width') == null || /^auto$/i.test(String(ccs.get('width')).trim());
        const natural = row ? (autoW ? Math.min(cb.w, __maxContentW(c)) : cb.w) : cb.h;
        return {
          el: c, box: cb,
          grow: num(ccs.get('flex-grow'), 0),
          shrink: num(ccs.get('flex-shrink'), 1),
          base: basisPx != null ? basisPx : natural,
          mMain: row ? mw : mh, mCross: row ? mh : mw,
        };
      });
      const gaps = gapMain * Math.max(0, items.length - 1);
      const used = items.reduce((a, it) => a + it.base + it.mMain, 0) + gaps;
      // Столбец без заданной высоты высок как его содержимое, но не ниже
      // `min-height` и не выше `max-height`. Мы брали ноль, и нехватка
      // сжимала всех детей в ничто.
      let inner = cw;
      if (!row) {
        if (explicitH != null) inner = explicitH;
        else {
          const lo = inH(len('min-height', baseH)), hi = inH(len('max-height', baseH));
          inner = used;
          if (hi != null && inner > hi) inner = hi;
          if (lo != null && inner < lo) inner = lo;
        }
      }
      let free = inner - used;
      if (free > 0) {
        const total = items.reduce((a, it) => a + it.grow, 0);
        if (total > 0) for (const it of items) it.main = it.base + free * (it.grow / total);
        else for (const it of items) it.main = it.base;
      } else if (free < 0) {
        const total = items.reduce((a, it) => a + it.shrink * it.base, 0);
        for (const it of items) {
          it.main = total > 0
            ? Math.max(0, it.base + free * ((it.shrink * it.base) / total))
            : it.base;
        }
      } else for (const it of items) it.main = it.base;
      const taken = items.reduce((a, it) => a + it.main + it.mMain, 0) + gaps;
      const slack = Math.max(0, inner - taken);
      let lead = 0, between = gapMain;
      if (justify === 'center') lead = slack / 2;
      else if (justify === 'flex-end' || justify === 'end' || justify === 'right') lead = slack;
      else if (justify === 'space-between' && items.length > 1) between += slack / (items.length - 1);
      else if (justify === 'space-around' && items.length) {
        lead = slack / items.length / 2; between += slack / items.length;
      } else if (justify === 'space-evenly' && items.length) {
        lead = slack / (items.length + 1); between += slack / (items.length + 1);
      }
      // Поперечный размер строки: заданная высота контейнера или самый
      // высокий ребёнок.
      const crossOuter = items.reduce((a, it) => Math.max(a, (row ? it.box.h : it.box.w) + it.mCross), 0);
      const lineCross = row
        ? (explicitH != null ? explicitH : crossOuter)
        : cw;
      const order = reverse ? items.slice().reverse() : items;
      let along = lead;
      for (const it of order) {
        const ccs = __cascadeFor(it.el);
        const self = String(ccs.get('align-self') || 'auto').toLowerCase();
        const how = self !== 'auto' && self !== 'normal' ? self : align;
        const cfs = __usedFontSize(it.el);
        const mLead = row ? (__lengthPx(ccs.get('margin-left'), cfs, cw) || 0)
                          : (__lengthPx(ccs.get('margin-top'), cfs, cw) || 0);
        const mCrossLead = row ? (__lengthPx(ccs.get('margin-top'), cfs, cw) || 0)
                               : (__lengthPx(ccs.get('margin-left'), cfs, cw) || 0);
        const natCross = row ? it.box.h : it.box.w;
        const stretch = (how === 'normal' || how === 'stretch')
          && (row ? explicitH != null || items.length > 0 : true);
        const crossSize = stretch ? Math.max(0, lineCross - it.mCross) : natCross;
        let crossPos = mCrossLead;
        if (!stretch) {
          if (how === 'center') crossPos = Math.max(0, (lineCross - natCross - it.mCross) / 2) + mCrossLead;
          else if (how === 'flex-end' || how === 'end') crossPos = Math.max(0, lineCross - natCross - it.mCross) + mCrossLead;
        }
        const x = row ? contentX + along + mLead : contentX + crossPos;
        const yy = row ? contentY + crossPos : contentY + along + mLead;
        const cb = __layoutOne(it.el, x - mLead, yy - (row ? mCrossLead : mLead), cw, fbox,
          row ? { w: it.main, h: stretch ? crossSize : null, block: true }
              : { w: stretch ? crossSize : null, h: it.main, block: true });
        if (cb) {
          widest = Math.max(widest, cb.x - contentX + cb.w);
          deepest = Math.max(deepest, cb.y - contentY + cb.h);
        }
        along += it.main + it.mMain + between;
      }
      // Промежуток ставится между детьми, а не после последнего.
      y = contentY + (row ? lineCross : Math.max(0, along - (order.length ? between : 0)));
      // Остальное — как у блока: абсолютные дети кладутся сами по себе.
      for (const c of boxedKids) {
        const p = String(__cascadeFor(c).get('position') || 'static').toLowerCase();
        if (p === 'absolute' || p === 'fixed') __layoutOne(c, contentX, contentY, cw, fbox);
      }
    } else {
      // Блоки ложатся друг под друга, строчные — в строку, и строка
      // переносится по ширине содержимого. Раньше всякий ребёнок начинал
      // новую строку, и два `<span>` подряд стояли лесенкой, а не рядом,
      // как у браузера.
      let i = 0;
      // Поля соседних блоков схлопываются: между двумя абзацами у браузера
      // шестнадцать пикселей, а не тридцать два. Поле первого и последнего
      // ребёнка уходит наружу, если у родителя нет ни рамки, ни отступа с
      // этой стороны, — и становится полем самого родителя.
      let carry = 0;          // нижнее поле предыдущего блока, ждёт схлопывания
      let firstFlow = true;
      const positionOf = (c) => String(__cascadeFor(c).get('position') || 'static').toLowerCase();
      while (i < boxedKids.length) {
        const c = boxedKids[i];
        const cpos = positionOf(c);
        if (cpos === 'absolute' || cpos === 'fixed') {
          const cb = __layoutOne(c, contentX, y, cw, fbox);
          if (cb) {
            widest = Math.max(widest, cb.x - contentX + cb.w);
            deepest = Math.max(deepest, cb.y - contentY + cb.h);
          }
          i++;
          continue;
        }
        if (!__isInlineLevel(c)) {
          const cb = __layoutOne(c, contentX, y, cw, fbox);
          i++;
          if (!cb) continue;
          const cmt = cb.mt || 0;
          // Наружу — только у первого в потоке и только через пустой край.
          // У соседей поля схлопываются в большее из двух: коробка встала на
          // своё поле, и добрать надо лишь разницу.
          // Отрицательные поля тоже схлопываются: итог — наибольшее
          // положительное плюс наименьшее отрицательное. Мы их отбрасывали,
          // и `margin-top: -15px` у chess.com не поднимал блок ни на пиксель.
          const escapes = firstFlow && !bt && !pt_;
          const shift = escapes ? -cmt : __collapseM(carry, cmt) - cmt;
          if (escapes) { escapedTop = cmt; hasEscapedTop = true; }
          if (shift) __ptShiftBox(c, cb.x, cb.y + shift);
          widest = Math.max(widest, cb.x - contentX + cb.w);
          deepest = Math.max(deepest, cb.y - contentY + cb.h);
          y = cb.y + cb.h;
          carry = cb.mb || 0;
          firstFlow = false;
          continue;
        }
        const run = [];
        while (i < boxedKids.length && __isInlineLevel(boxedKids[i])
               && positionOf(boxedKids[i]) !== 'absolute' && positionOf(boxedKids[i]) !== 'fixed') {
          run.push(boxedKids[i++]);
        }
        // Строка соседствует с блоком через полное поле: схлопывать нечему.
        const done = __layoutInlineRun(run, contentX, y + carry, cw, fbox, lineH);
        y = done.y;
        carry = 0;
        firstFlow = false;
        widest = Math.max(widest, done.widest);
        deepest = Math.max(deepest, y - contentY);
      }
      // Нижнее поле последнего ребёнка остаётся внутри только тогда, когда
      // край родителя не пуст.
      if (carry && (bb || pb)) y += carry;
      else if (carry) escapedBottom = carry;
    }
    // Убежавшее поле становится полем самого родителя: блок с абзацем внутри
    // стоит у браузера на шестнадцать пикселей ниже, чем встал бы без этого,
    // а дети внутри — там же, где были.
    const collapsedTop = hasEscapedTop ? __collapseM(mt, escapedTop) : mt;
    if (collapsedTop !== mt) {
      const delta = collapsedTop - mt;
      for (const c of boxedKids) {
        if (c.__ptBox) __ptShiftBox(c, c.__ptBox.x, c.__ptBox.y + delta);
      }
      boxY += delta; contentY += delta; y += delta;
      mt = collapsedTop;
    }
    if (escapedBottom) mb = __collapseM(mb, escapedBottom);
    if (inlineish && explicitW == null && !forcedW && boxedKids.length) cw = widest;

    let ch;
    let lines = null;
    const ownText = __OWN_TEXT(el);
    if (ownText && !boxedKids.length) {
      lines = __wrapLines(ownText, inlineish && explicitW == null && !forcedW ? 0 : cw, fs, family, bold);
      if (inlineish && explicitW == null && !forcedW && lines.length === 1) cw = lines[0].width;
    }
    if (forced && forced.h != null) ch = Math.max(0, forced.h - pt_ - pb - bt - bb);
    else if (explicitH != null) ch = explicitH;
    else if (attrH != null) ch = attrH;
    else if (boxedKids.length) ch = Math.max(0, y - contentY);
    else if (lines && lines.length) ch = lines.length * lineH;
    // Пустая строчная коробка высоты не имеет: `inline-block` без содержимого
    // у браузера нулевой, а не в строку высотой.
    else ch = (inlineish && display === 'inline') ? Math.round(lineH) : 0;

    // Строчный элемент высок настолько, насколько высоки его чернила, а не
    // строка целиком. Заменяемого это не касается: у `<iframe width height>`
    // размер назван в атрибуте, и он главнее.
    if (inlineish && display === 'inline' && !frame
        && explicitH == null && attrH == null && !boxedKids.length && !(lines && lines.length)) {
      ch = fbox.asc + fbox.desc;
    }
    if (ua && explicitH == null && attrH == null) ch = ua.h;
    {
      const maxH = inH(len('max-height', baseH));
      const minH = inH(len('min-height', baseH));
      if (maxH != null && ch > maxH) ch = maxH;
      if (minH != null && ch < minH) ch = minH;
    }

    // Браузер держит длины в шестьдесят четвёртых пикселя, и это видно:
    // ширина строки 72.26171875 у нас против 72.265625 у Chrome — та же
    // величина, округлённая до его шага.
    // Браузер держит длины в шестьдесят четвёртых пикселя и **отбрасывает**
    // остаток, а не округляет: высота строки 22,4 становится 22,390625, а не
    // 22,40625. Разница видна в каждом дробном размере.
    const q = (v) => Math.floor(v * 64) / 64;
    const box = {
      x: q(boxX), y: q(boxY),
      w: q(cw + pl + pr + bl + br),
      h: q(ch + pt_ + pb + bt + bb),
      cw: q(cw), ch: q(ch), cx: q(contentX), cy: q(contentY),
      bx: bl + br, by: bt + bb, mb,
      mt: q(mt), mr: q(mr), ml: q(ml),
      line: lineH, inline: inlineish, lineTop: q(boxY), lines,
      asc: fbox.asc, desc: fbox.desc,
      // Область прокрутки — по содержимому, а не по самой коробке; полоса
      // прокрутки, если она есть, отъедает пятнадцать пикселей у видимой части.
      sw: q(Math.max(cw, widest)), sh: q(Math.max(ch, deepest)),
      bar: [0, 0],
    };
    // Полоса прокрутки занимает место: у блока с `overflow: auto`, чьё
    // содержимое не влезает, видимая часть на пятнадцать пикселей уже и ниже.
    // Мы отвечали полным размером, то есть страницей без полос вообще.
    {
      const needX = (ovX === 'scroll') || (ovX === 'auto' && widest > cw + 0.5);
      const needY = (ovY === 'scroll') || (ovY === 'auto' && deepest > ch + 0.5);
      box.bar = [needY ? 15 : 0, needX ? 15 : 0];
    }
    if (box.inline && strut) {
      // Выравнивание по базовой линии, а не по центру: браузер ставит строчный
      // элемент так, чтобы его базовая линия легла на базовую линию строки.
      // `<span>` в тринадцать пикселей внутри шестнадцатипиксельного текста
      // опускается ровно на разницу подъёмов — на два пикселя.
      const shift = Math.max(0, strut.asc - fbox.asc);
      box.y = q(box.y + shift);
      box.cy = q(box.cy + shift);
    }
    el.__ptBox = box;
    el.__ptBoxV = __layoutBuilt;
    // Кадр поменял размер — у его окна поменялся и вид.
    if (tag === 'iframe' && el.__ptRealm) __ptTellFrame(el, box);
    return box;
  }

  // Сообщить окну кадра его размер. Кадра без коробки — `display: none` —
  // браузер не раскладывает совсем, и об этом окну тоже надо сказать.
  function __ptTellFrame(el, box) {
    const w = el.__ptRealm;
    if (!w) return;
    try {
      if (!box) {
        if (typeof w.__pt_setRendered === 'function') w.__pt_setRendered(false);
        // Окно кадра без коробки — нулевое: innerWidth/innerHeight у Chrome 0.
        if ((el.__ptSeenW !== 0 || el.__ptSeenH !== 0) && typeof w.__pt_setViewport === 'function') {
          el.__ptSeenW = 0; el.__ptSeenH = 0;
          w.__pt_setViewport(0, 0);
        }
        return;
      }
      if (typeof w.__pt_setRendered === 'function') w.__pt_setRendered(true);
      if (el.__ptSeenW === box.cw && el.__ptSeenH === box.ch) return;
      el.__ptSeenW = box.cw; el.__ptSeenH = box.ch;
      if (typeof w.__pt_setViewport === 'function') w.__pt_setViewport(box.cw, box.ch);
    } catch (e) {}
  }

  // Кадры, у которых есть своё окно: после каждой раскладки им говорят,
  // что с ними стало, — спрятанному тоже.
  const __realmFrames = new Set();

  function __relayout() {
    if (__layoutBuilt === __layoutSeq) return;
    __layoutBuilt = __layoutSeq;
    __collectHidden();
    __rows = [];
    __boxes = [];
    const doc = globalThis.document;
    const de = doc && doc.documentElement;
    if (!de) return;
    // Отметка раскладки держится на самом документе: коробки его узлов
    // читает и соседний реалм — окно страницы меряет тело своего кадра, — а
    // свой счётчик у каждого реалма собственный, и чужие коробки по нему
    // выходили то пустыми, то устаревшими.
    try {
      Object.defineProperty(doc, '__ptLayoutV', { value: __layoutBuilt, configurable: true, enumerable: false, writable: true });
      if (typeof doc.__ptRelayout !== 'function') {
        Object.defineProperty(doc, '__ptRelayout', { value: () => __relayout(), configurable: true, enumerable: false });
      }
    } catch (e) {}
    if (!__rendered) return;
    __layoutOne(de, 0, 0, LAYOUT.W);
    // В режиме совместимости корень и тело тянутся на всё окно: у пустого
    // кадра 300×150 браузер отвечает высотой 150 у `html` и 134 у тела, а не
    // высотой строки. Кадр без доктайпа — обычное дело: `about:blank` и
    // `srcdoc` идут именно так.
    try {
      if (doc.compatMode === 'BackCompat') {
        const stretch = (el, avail) => {
          const b = el && el.__ptBox;
          if (!b || avail == null) return null;
          const outer = b.h + (b.mt || 0) + (b.mb || 0);
          if (outer >= avail) return b.ch;
          const grown = avail - (b.mt || 0) - (b.mb || 0) - (b.by || 0);
          b.ch = grown;
          b.h = grown + (b.by || 0);
          return grown;
        };
        const inner = stretch(de, LAYOUT.H);
        stretch(doc.body, inner);
      }
    } catch (e) {}
    // Порядок обхода — порядок наложения: попадание в точку ищется с конца, то
    // есть от самого глубокого и позднего, как в браузере.
    __rows = __boxes;
    // Спрятанные кадры в обход не попадают, а сказать им надо: пока им не
    // скажут, внутри останется старая раскладка.
    for (const f of __realmFrames) {
      if (!f.isConnected) { __realmFrames.delete(f); continue; }
      if (f.__ptBoxV !== __layoutBuilt) __ptTellFrame(f, null);
    }
  }

  // Width/height an element declares for itself: the CSS `width`/`height` it was
  // given, else the presentational attributes `<iframe width height>`/`<img>`/
  // `<canvas>` carry. Percentages and other units are left to the row default —
  // guessing at them would be worse than admitting we do not lay out.
  function __declaredSize(el) {
    const out = { w: null, h: null };
    const px = (v) => {
      if (v == null) return null;
      const m = /^\s*(\d+(?:\.\d+)?)(px)?\s*$/.exec(String(v));
      return m ? Math.round(parseFloat(m[1])) : null;
    };
    const st = el.style;
    if (st) { out.w = px(st.width); out.h = px(st.height); }
    if (out.w == null && el.getAttribute) out.w = px(__ptGetA(el, 'width'));
    if (out.h == null && el.getAttribute) out.h = px(__ptGetA(el, 'height'));
    return out;
  }

  // getComputedStyle: у браузера это 456 свойств с разрешёнными значениями, у
  // нас была заглушка с двумя. Загрузчик Cloudflare меряет свой виджет именно
  // так — `getComputedStyle(iframe)` — и пустой ответ читается как «элемента не
  // видно». Таблицы сняты с Chrome 148: порядок имён, значения по умолчанию для
  // блочного элемента и дельты для строчного и заменяемого.
const CS_ORDER = ["accent-color","align-content","align-items","align-self","alignment-baseline","anchor-name","anchor-scope","animation-composition","animation-delay","animation-direction","animation-duration","animation-fill-mode","animation-iteration-count","animation-name","animation-play-state","animation-range-end","animation-range-start","animation-timeline","animation-timing-function","animation-trigger","app-region","appearance","aspect-ratio","backdrop-filter","backface-visibility","background-attachment","background-blend-mode","background-clip","background-color","background-image","background-origin","background-position","background-repeat","background-size","baseline-shift","baseline-source","block-size","border-block-end-color","border-block-end-style","border-block-end-width","border-block-start-color","border-block-start-style","border-block-start-width","border-bottom-color","border-bottom-left-radius","border-bottom-right-radius","border-bottom-style","border-bottom-width","border-collapse","border-end-end-radius","border-end-start-radius","border-image-outset","border-image-repeat","border-image-slice","border-image-source","border-image-width","border-inline-end-color","border-inline-end-style","border-inline-end-width","border-inline-start-color","border-inline-start-style","border-inline-start-width","border-left-color","border-left-style","border-left-width","border-right-color","border-right-style","border-right-width","border-shape","border-start-end-radius","border-start-start-radius","border-top-color","border-top-left-radius","border-top-right-radius","border-top-style","border-top-width","bottom","box-decoration-break","box-shadow","box-sizing","break-after","break-before","break-inside","buffered-rendering","caption-side","caret-animation","caret-color","caret-shape","clear","clip","clip-path","clip-rule","color","color-interpolation","color-interpolation-filters","color-rendering","color-scheme","column-count","column-fill","column-gap","column-height","column-rule-break","column-rule-color","column-rule-inset-cap-end","column-rule-inset-cap-start","column-rule-inset-junction-end","column-rule-inset-junction-start","column-rule-style","column-rule-visibility-items","column-rule-width","column-span","column-width","column-wrap","contain","contain-intrinsic-block-size","contain-intrinsic-height","contain-intrinsic-inline-size","contain-intrinsic-size","contain-intrinsic-width","container-name","container-type","content","content-visibility","corner-bottom-left-shape","corner-bottom-right-shape","corner-end-end-shape","corner-end-start-shape","corner-start-end-shape","corner-start-start-shape","corner-top-left-shape","corner-top-right-shape","counter-increment","counter-reset","counter-set","cursor","cx","cy","d","direction","display","dominant-baseline","dynamic-range-limit","empty-cells","field-sizing","fill","fill-opacity","fill-rule","filter","flex-basis","flex-direction","flex-grow","flex-line-count","flex-shrink","flex-wrap","float","flood-color","flood-opacity","font-family","font-feature-settings","font-kerning","font-language-override","font-optical-sizing","font-palette","font-size","font-size-adjust","font-stretch","font-style","font-synthesis-small-caps","font-synthesis-style","font-synthesis-weight","font-variant","font-variant-alternates","font-variant-caps","font-variant-east-asian","font-variant-emoji","font-variant-ligatures","font-variant-numeric","font-variant-position","font-variation-settings","font-weight","forced-color-adjust","grid-auto-columns","grid-auto-flow","grid-auto-rows","grid-column-end","grid-column-start","grid-row-end","grid-row-start","grid-template-areas","grid-template-columns","grid-template-rows","height","hyphenate-character","hyphenate-limit-chars","hyphens","image-orientation","image-rendering","initial-letter","inline-size","inset-block-end","inset-block-start","inset-inline-end","inset-inline-start","interactivity","interest-delay-end","interest-delay-start","interpolate-size","isolation","justify-content","justify-items","justify-self","left","letter-spacing","lighting-color","line-break","line-height","list-style-image","list-style-position","list-style-type","margin-block-end","margin-block-start","margin-bottom","margin-inline-end","margin-inline-start","margin-left","margin-right","margin-top","marker-end","marker-mid","marker-start","mask-clip","mask-composite","mask-image","mask-mode","mask-origin","mask-position","mask-repeat","mask-size","mask-type","math-depth","math-shift","math-style","max-block-size","max-height","max-inline-size","max-width","min-block-size","min-height","min-inline-size","min-width","mix-blend-mode","object-fit","object-position","object-view-box","offset-anchor","offset-distance","offset-path","offset-position","offset-rotate","opacity","order","orphans","outline-color","outline-offset","outline-style","outline-width","overflow-anchor","overflow-block","overflow-clip-margin","overflow-inline","overflow-wrap","overflow-x","overflow-y","overlay","overscroll-behavior-block","overscroll-behavior-inline","overscroll-behavior-x","overscroll-behavior-y","padding-block-end","padding-block-start","padding-bottom","padding-inline-end","padding-inline-start","padding-left","padding-right","padding-top","paint-order","perspective","perspective-origin","pointer-events","position","position-anchor","position-area","position-try-fallbacks","position-try-order","position-visibility","print-color-adjust","quotes","r","reading-flow","reading-order","resize","right","rotate","row-gap","row-rule-break","row-rule-color","row-rule-inset-cap-end","row-rule-inset-cap-start","row-rule-inset-junction-end","row-rule-inset-junction-start","row-rule-style","row-rule-visibility-items","row-rule-width","ruby-align","ruby-overhang","ruby-position","rule-overlap","rx","ry","scale","scroll-behavior","scroll-initial-target","scroll-margin-block-end","scroll-margin-block-start","scroll-margin-bottom","scroll-margin-inline-end","scroll-margin-inline-start","scroll-margin-left","scroll-margin-right","scroll-margin-top","scroll-marker-group","scroll-padding-block-end","scroll-padding-block-start","scroll-padding-bottom","scroll-padding-inline-end","scroll-padding-inline-start","scroll-padding-left","scroll-padding-right","scroll-padding-top","scroll-snap-align","scroll-snap-stop","scroll-snap-type","scroll-target-group","scroll-timeline-axis","scroll-timeline-name","scrollbar-color","scrollbar-gutter","scrollbar-width","shape-image-threshold","shape-margin","shape-outside","shape-rendering","speak","stop-color","stop-opacity","stroke","stroke-dasharray","stroke-dashoffset","stroke-linecap","stroke-linejoin","stroke-miterlimit","stroke-opacity","stroke-width","tab-size","table-layout","text-align","text-align-last","text-anchor","text-autospace","text-box-edge","text-box-trim","text-combine-upright","text-decoration","text-decoration-color","text-decoration-line","text-decoration-skip-ink","text-decoration-style","text-decoration-thickness","text-emphasis-color","text-emphasis-position","text-emphasis-style","text-fit","text-indent","text-justify","text-orientation","text-overflow","text-rendering","text-shadow","text-size-adjust","text-spacing-trim","text-transform","text-underline-offset","text-underline-position","text-wrap-mode","text-wrap-style","timeline-scope","timeline-trigger-activation-range-end","timeline-trigger-activation-range-start","timeline-trigger-active-range-end","timeline-trigger-active-range-start","timeline-trigger-name","timeline-trigger-source","top","touch-action","transform","transform-box","transform-origin","transform-style","transition-behavior","transition-delay","transition-duration","transition-property","transition-timing-function","translate","trigger-scope","unicode-bidi","user-select","vector-effect","vertical-align","view-timeline-axis","view-timeline-inset","view-timeline-name","view-transition-class","view-transition-group","view-transition-name","view-transition-scope","visibility","white-space-collapse","widows","width","will-change","word-break","word-spacing","writing-mode","x","y","z-index","zoom","-webkit-border-horizontal-spacing","-webkit-border-image","-webkit-border-vertical-spacing","-webkit-box-align","-webkit-box-decoration-break","-webkit-box-direction","-webkit-box-flex","-webkit-box-ordinal-group","-webkit-box-orient","-webkit-box-pack","-webkit-box-reflect","-webkit-font-smoothing","-webkit-line-break","-webkit-line-clamp","-webkit-locale","-webkit-mask-box-image","-webkit-mask-box-image-outset","-webkit-mask-box-image-repeat","-webkit-mask-box-image-slice","-webkit-mask-box-image-source","-webkit-mask-box-image-width","-webkit-mask-position-x","-webkit-mask-position-y","-webkit-rtl-ordering","-webkit-ruby-position","-webkit-tap-highlight-color","-webkit-text-combine","-webkit-text-decorations-in-effect","-webkit-text-fill-color","-webkit-text-orientation","-webkit-text-security","-webkit-text-stroke-color","-webkit-text-stroke-width","-webkit-user-drag","-webkit-user-modify","-webkit-writing-mode"];
const CS_BASE = {"accent-color":"auto","align-content":"normal","align-items":"normal","align-self":"auto","alignment-baseline":"auto","anchor-name":"none","anchor-scope":"none","animation-composition":"replace","animation-delay":"0s","animation-direction":"normal","animation-duration":"0s","animation-fill-mode":"none","animation-iteration-count":"1","animation-name":"none","animation-play-state":"running","animation-range-end":"normal","animation-range-start":"normal","animation-timeline":"auto","animation-timing-function":"ease","animation-trigger":"none","app-region":"none","appearance":"none","aspect-ratio":"auto","backdrop-filter":"none","backface-visibility":"visible","background-attachment":"scroll","background-blend-mode":"normal","background-clip":"border-box","background-color":"rgba(0, 0, 0, 0)","background-image":"none","background-origin":"padding-box","background-position":"0% 0%","background-repeat":"repeat","background-size":"auto","baseline-shift":"0px","baseline-source":"auto","block-size":"auto","border-block-end-color":"rgb(0, 0, 0)","border-block-end-style":"none","border-block-end-width":"0px","border-block-start-color":"rgb(0, 0, 0)","border-block-start-style":"none","border-block-start-width":"0px","border-bottom-color":"rgb(0, 0, 0)","border-bottom-left-radius":"0px","border-bottom-right-radius":"0px","border-bottom-style":"none","border-bottom-width":"0px","border-collapse":"separate","border-end-end-radius":"0px","border-end-start-radius":"0px","border-image-outset":"0","border-image-repeat":"stretch","border-image-slice":"100%","border-image-source":"none","border-image-width":"1","border-inline-end-color":"rgb(0, 0, 0)","border-inline-end-style":"none","border-inline-end-width":"0px","border-inline-start-color":"rgb(0, 0, 0)","border-inline-start-style":"none","border-inline-start-width":"0px","border-left-color":"rgb(0, 0, 0)","border-left-style":"none","border-left-width":"0px","border-right-color":"rgb(0, 0, 0)","border-right-style":"none","border-right-width":"0px","border-shape":"none","border-start-end-radius":"0px","border-start-start-radius":"0px","border-top-color":"rgb(0, 0, 0)","border-top-left-radius":"0px","border-top-right-radius":"0px","border-top-style":"none","border-top-width":"0px","bottom":"auto","box-decoration-break":"slice","box-shadow":"none","box-sizing":"content-box","break-after":"auto","break-before":"auto","break-inside":"auto","buffered-rendering":"auto","caption-side":"top","caret-animation":"auto","caret-color":"rgb(0, 0, 0)","caret-shape":"auto","clear":"none","clip":"auto","clip-path":"none","clip-rule":"nonzero","color":"rgb(0, 0, 0)","color-interpolation":"srgb","color-interpolation-filters":"linearrgb","color-rendering":"auto","color-scheme":"normal","column-count":"auto","column-fill":"balance","column-gap":"normal","column-height":"auto","column-rule-break":"normal","column-rule-color":"rgb(0, 0, 0)","column-rule-inset-cap-end":"0px","column-rule-inset-cap-start":"0px","column-rule-inset-junction-end":"0px","column-rule-inset-junction-start":"0px","column-rule-style":"none","column-rule-visibility-items":"normal","column-rule-width":"3px","column-span":"none","column-width":"auto","column-wrap":"auto","contain":"none","contain-intrinsic-block-size":"none","contain-intrinsic-height":"none","contain-intrinsic-inline-size":"none","contain-intrinsic-size":"none","contain-intrinsic-width":"none","container-name":"none","container-type":"normal","content":"normal","content-visibility":"visible","corner-bottom-left-shape":"round","corner-bottom-right-shape":"round","corner-end-end-shape":"round","corner-end-start-shape":"round","corner-start-end-shape":"round","corner-start-start-shape":"round","corner-top-left-shape":"round","corner-top-right-shape":"round","counter-increment":"none","counter-reset":"none","counter-set":"none","cursor":"auto","cx":"0px","cy":"0px","d":"none","direction":"ltr","display":"block","dominant-baseline":"auto","dynamic-range-limit":"no-limit","empty-cells":"show","field-sizing":"fixed","fill":"rgb(0, 0, 0)","fill-opacity":"1","fill-rule":"nonzero","filter":"none","flex-basis":"auto","flex-direction":"row","flex-grow":"0","flex-line-count":"1","flex-shrink":"1","flex-wrap":"nowrap","float":"none","flood-color":"rgb(0, 0, 0)","flood-opacity":"1","font-family":"\"Times New Roman\"","font-feature-settings":"normal","font-kerning":"auto","font-language-override":"normal","font-optical-sizing":"auto","font-palette":"normal","font-size":"16px","font-size-adjust":"none","font-stretch":"100%","font-style":"normal","font-synthesis-small-caps":"auto","font-synthesis-style":"auto","font-synthesis-weight":"auto","font-variant":"normal","font-variant-alternates":"normal","font-variant-caps":"normal","font-variant-east-asian":"normal","font-variant-emoji":"normal","font-variant-ligatures":"normal","font-variant-numeric":"normal","font-variant-position":"normal","font-variation-settings":"normal","font-weight":"400","forced-color-adjust":"auto","grid-auto-columns":"auto","grid-auto-flow":"row","grid-auto-rows":"auto","grid-column-end":"auto","grid-column-start":"auto","grid-row-end":"auto","grid-row-start":"auto","grid-template-areas":"none","grid-template-columns":"none","grid-template-rows":"none","height":"auto","hyphenate-character":"auto","hyphenate-limit-chars":"auto","hyphens":"manual","image-orientation":"from-image","image-rendering":"auto","initial-letter":"normal","inline-size":"auto","inset-block-end":"auto","inset-block-start":"auto","inset-inline-end":"auto","inset-inline-start":"auto","interactivity":"auto","interest-delay-end":"normal","interest-delay-start":"normal","interpolate-size":"numeric-only","isolation":"auto","justify-content":"normal","justify-items":"normal","justify-self":"auto","left":"auto","letter-spacing":"normal","lighting-color":"rgb(255, 255, 255)","line-break":"auto","line-height":"normal","list-style-image":"none","list-style-position":"outside","list-style-type":"disc","margin-block-end":"0px","margin-block-start":"0px","margin-bottom":"0px","margin-inline-end":"0px","margin-inline-start":"0px","margin-left":"0px","margin-right":"0px","margin-top":"0px","marker-end":"none","marker-mid":"none","marker-start":"none","mask-clip":"border-box","mask-composite":"add","mask-image":"none","mask-mode":"match-source","mask-origin":"border-box","mask-position":"0% 0%","mask-repeat":"repeat","mask-size":"auto","mask-type":"luminance","math-depth":"0","math-shift":"normal","math-style":"normal","max-block-size":"none","max-height":"none","max-inline-size":"none","max-width":"none","min-block-size":"0px","min-height":"0px","min-inline-size":"0px","min-width":"0px","mix-blend-mode":"normal","object-fit":"fill","object-position":"50% 50%","object-view-box":"none","offset-anchor":"auto","offset-distance":"0px","offset-path":"none","offset-position":"normal","offset-rotate":"auto 0deg","opacity":"1","order":"0","orphans":"2","outline-color":"rgb(0, 0, 0)","outline-offset":"0px","outline-style":"none","outline-width":"3px","overflow-anchor":"auto","overflow-block":"visible","overflow-clip-margin":"0px","overflow-inline":"visible","overflow-wrap":"normal","overflow-x":"visible","overflow-y":"visible","overlay":"none","overscroll-behavior-block":"auto","overscroll-behavior-inline":"auto","overscroll-behavior-x":"auto","overscroll-behavior-y":"auto","padding-block-end":"0px","padding-block-start":"0px","padding-bottom":"0px","padding-inline-end":"0px","padding-inline-start":"0px","padding-left":"0px","padding-right":"0px","padding-top":"0px","paint-order":"normal","perspective":"none","perspective-origin":"50% 50%","pointer-events":"auto","position":"static","position-anchor":"normal","position-area":"none","position-try-fallbacks":"none","position-try-order":"normal","position-visibility":"anchors-visible","print-color-adjust":"economy","quotes":"auto","r":"0px","reading-flow":"normal","reading-order":"0","resize":"none","right":"auto","rotate":"none","row-gap":"normal","row-rule-break":"normal","row-rule-color":"rgb(0, 0, 0)","row-rule-inset-cap-end":"0px","row-rule-inset-cap-start":"0px","row-rule-inset-junction-end":"0px","row-rule-inset-junction-start":"0px","row-rule-style":"none","row-rule-visibility-items":"normal","row-rule-width":"3px","ruby-align":"space-around","ruby-overhang":"auto","ruby-position":"over","rule-overlap":"row-over-column","rx":"auto","ry":"auto","scale":"none","scroll-behavior":"auto","scroll-initial-target":"none","scroll-margin-block-end":"0px","scroll-margin-block-start":"0px","scroll-margin-bottom":"0px","scroll-margin-inline-end":"0px","scroll-margin-inline-start":"0px","scroll-margin-left":"0px","scroll-margin-right":"0px","scroll-margin-top":"0px","scroll-marker-group":"none","scroll-padding-block-end":"auto","scroll-padding-block-start":"auto","scroll-padding-bottom":"auto","scroll-padding-inline-end":"auto","scroll-padding-inline-start":"auto","scroll-padding-left":"auto","scroll-padding-right":"auto","scroll-padding-top":"auto","scroll-snap-align":"none","scroll-snap-stop":"normal","scroll-snap-type":"none","scroll-target-group":"none","scroll-timeline-axis":"block","scroll-timeline-name":"none","scrollbar-color":"auto","scrollbar-gutter":"auto","scrollbar-width":"auto","shape-image-threshold":"0","shape-margin":"0px","shape-outside":"none","shape-rendering":"auto","speak":"normal","stop-color":"rgb(0, 0, 0)","stop-opacity":"1","stroke":"none","stroke-dasharray":"none","stroke-dashoffset":"0px","stroke-linecap":"butt","stroke-linejoin":"miter","stroke-miterlimit":"4","stroke-opacity":"1","stroke-width":"1px","tab-size":"8","table-layout":"auto","text-align":"start","text-align-last":"auto","text-anchor":"start","text-autospace":"no-autospace","text-box-edge":"auto","text-box-trim":"none","text-combine-upright":"none","text-decoration":"none","text-decoration-color":"rgb(0, 0, 0)","text-decoration-line":"none","text-decoration-skip-ink":"auto","text-decoration-style":"solid","text-decoration-thickness":"auto","text-emphasis-color":"rgb(0, 0, 0)","text-emphasis-position":"over","text-emphasis-style":"none","text-fit":"none","text-indent":"0px","text-justify":"auto","text-orientation":"mixed","text-overflow":"clip","text-rendering":"auto","text-shadow":"none","text-size-adjust":"auto","text-spacing-trim":"normal","text-transform":"none","text-underline-offset":"auto","text-underline-position":"auto","text-wrap-mode":"wrap","text-wrap-style":"auto","timeline-scope":"none","timeline-trigger-activation-range-end":"normal","timeline-trigger-activation-range-start":"normal","timeline-trigger-active-range-end":"auto","timeline-trigger-active-range-start":"auto","timeline-trigger-name":"none","timeline-trigger-source":"auto","top":"auto","touch-action":"auto","transform":"none","transform-box":"view-box","transform-origin":"50% 50%","transform-style":"flat","transition-behavior":"normal","transition-delay":"0s","transition-duration":"0s","transition-property":"all","transition-timing-function":"ease","translate":"none","trigger-scope":"none","unicode-bidi":"isolate","user-select":"auto","vector-effect":"none","vertical-align":"baseline","view-timeline-axis":"block","view-timeline-inset":"auto","view-timeline-name":"none","view-transition-class":"none","view-transition-group":"normal","view-transition-name":"none","view-transition-scope":"none","visibility":"visible","white-space-collapse":"collapse","widows":"2","width":"auto","will-change":"auto","word-break":"normal","word-spacing":"0px","writing-mode":"horizontal-tb","x":"0px","y":"0px","z-index":"auto","zoom":"1","-webkit-border-horizontal-spacing":"0px","-webkit-border-image":"none","-webkit-border-vertical-spacing":"0px","-webkit-box-align":"stretch","-webkit-box-decoration-break":"slice","-webkit-box-direction":"normal","-webkit-box-flex":"0","-webkit-box-ordinal-group":"1","-webkit-box-orient":"horizontal","-webkit-box-pack":"start","-webkit-box-reflect":"none","-webkit-font-smoothing":"auto","-webkit-line-break":"auto","-webkit-line-clamp":"none","-webkit-locale":"auto","-webkit-mask-box-image":"none","-webkit-mask-box-image-outset":"0","-webkit-mask-box-image-repeat":"stretch","-webkit-mask-box-image-slice":"0 fill","-webkit-mask-box-image-source":"none","-webkit-mask-box-image-width":"auto","-webkit-mask-position-x":"0%","-webkit-mask-position-y":"0%","-webkit-rtl-ordering":"logical","-webkit-ruby-position":"before","-webkit-tap-highlight-color":"rgba(0, 0, 0, 0.18)","-webkit-text-combine":"none","-webkit-text-decorations-in-effect":"none","-webkit-text-fill-color":"rgb(0, 0, 0)","-webkit-text-orientation":"vertical-right","-webkit-text-security":"none","-webkit-text-stroke-color":"rgb(0, 0, 0)","-webkit-text-stroke-width":"0px","-webkit-user-drag":"auto","-webkit-user-modify":"read-only","-webkit-writing-mode":"horizontal-tb"};
const CS_INLINE = {"block-size":"auto","display":"inline","height":"auto","inline-size":"auto","perspective-origin":"0px 0px","transform-origin":"0px 0px","unicode-bidi":"normal","width":"auto"};
const CS_REPLACED = {"block-size":"150px","border-block-end-style":"inset","border-block-end-width":"2px","border-block-start-style":"inset","border-block-start-width":"2px","border-bottom-style":"inset","border-bottom-width":"2px","border-inline-end-style":"inset","border-inline-end-width":"2px","border-inline-start-style":"inset","border-inline-start-width":"2px","border-left-style":"inset","border-left-width":"2px","border-right-style":"inset","border-right-width":"2px","border-top-style":"inset","border-top-width":"2px","display":"inline","height":"150px","inline-size":"300px","overflow-block":"clip","overflow-clip-margin":"content-box","overflow-inline":"clip","overflow-x":"clip","overflow-y":"clip","perspective-origin":"152px 77px","transform-origin":"152px 77px","unicode-bidi":"normal","width":"300px"};
  const CS_DISPLAY = {
    span: 'inline', a: 'inline', b: 'inline', i: 'inline', em: 'inline', strong: 'inline',
    small: 'inline', code: 'inline', label: 'inline', abbr: 'inline', cite: 'inline',
    q: 'inline', s: 'inline', u: 'inline', sub: 'inline', sup: 'inline', mark: 'inline',
    time: 'inline', var: 'inline', samp: 'inline', kbd: 'inline', bdi: 'inline', bdo: 'inline',
    img: 'inline', iframe: 'inline', canvas: 'inline', video: 'inline', audio: 'inline',
    circle: 'inline', path: 'inline', line: 'inline', g: 'inline', text: 'inline',
    rect: 'inline', ellipse: 'inline', polyline: 'inline', polygon: 'inline',
    object: 'inline', embed: 'inline', svg: 'inline', input: 'inline-block',
    button: 'inline-block', select: 'inline-block', textarea: 'inline-block',
    meter: 'inline-block', progress: 'inline-block', li: 'list-item', table: 'table',
    thead: 'table-header-group', tbody: 'table-row-group', tfoot: 'table-footer-group',
    tr: 'table-row', td: 'table-cell', th: 'table-cell', caption: 'table-caption',
    head: 'none', style: 'none', script: 'none', link: 'none', meta: 'none',
    title: 'none', template: 'none', base: 'none', param: 'none', source: 'none',
    track: 'none', option: 'block', optgroup: 'block',
    output: 'inline', tt: 'inline', br: 'inline', wbr: 'inline',
    col: 'table-column', colgroup: 'table-column-group', audio: 'none',
  };
  const CS_REPLACED_TAGS = new Set(['iframe', 'img', 'canvas', 'video', 'audio', 'object', 'embed']);
  const CS_CAMEL = (n) => n.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

  // Наследуемые свойства. У нас их не наследовал никто: `<div>` внутри `<body>`
  // с заданным шрифтом отвечал шрифтом по умолчанию, то есть противоречил
  // собственной странице. Список — из спецификации; проверен на Chrome по
  // цвету, шрифту, высоте строки и выключке.
  const CSS_INHERITED = new Set([
    'azimuth', 'border-collapse', 'border-spacing', 'caption-side', 'caret-color',
    'color', 'color-scheme', 'cursor', 'direction', 'empty-cells', 'font',
    'font-family', 'font-feature-settings', 'font-kerning', 'font-language-override',
    'font-optical-sizing', 'font-palette', 'font-size', 'font-size-adjust',
    'font-stretch', 'font-style', 'font-synthesis-small-caps', 'font-synthesis-style',
    'font-synthesis-weight', 'font-variant', 'font-variant-alternates',
    'font-variant-caps', 'font-variant-east-asian', 'font-variant-emoji',
    'font-variant-ligatures', 'font-variant-numeric', 'font-variant-position',
    'font-variation-settings', 'font-weight', 'forced-color-adjust', 'hyphenate-character',
    'hyphenate-limit-chars', 'hyphens', 'image-orientation', 'image-rendering',
    'letter-spacing', 'line-break', 'line-height', 'list-style', 'list-style-image',
    'list-style-position', 'list-style-type', 'math-depth', 'math-shift', 'math-style',
    'orphans', 'overflow-wrap', 'paint-order', 'pointer-events', 'print-color-adjust',
    'quotes', 'ruby-align', 'ruby-position', 'scrollbar-color', 'speak',
    'tab-size', 'text-align', 'text-align-last', 'text-anchor', 'text-autospace',
    'text-combine-upright', 'text-decoration-skip-ink', 'text-emphasis-color',
    'text-emphasis-position', 'text-emphasis-style', 'text-indent', 'text-justify',
    'text-orientation', 'text-rendering', 'text-shadow', 'text-size-adjust',
    'text-spacing-trim', 'text-transform', 'text-underline-offset',
    'text-underline-position', 'text-wrap-mode', 'text-wrap-style', 'visibility',
    'white-space-collapse', 'widows', 'word-break', 'word-spacing', 'writing-mode',
    'fill', 'fill-opacity', 'fill-rule', 'stroke', 'stroke-dasharray',
    'stroke-dashoffset', 'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit',
    'stroke-opacity', 'stroke-width', 'clip-rule', 'color-interpolation',
    'color-rendering', 'dominant-baseline', 'marker-end', 'marker-mid', 'marker-start',
    'shape-rendering', 'stop-color', 'stop-opacity', '-webkit-font-smoothing',
    '-webkit-locale', '-webkit-text-fill-color', '-webkit-text-stroke-color',
    '-webkit-text-stroke-width', '-webkit-rtl-ordering', '-webkit-line-break',
    '-webkit-text-orientation', '-webkit-text-security', '-webkit-user-modify',
    '-webkit-writing-mode', '-webkit-border-horizontal-spacing',
    '-webkit-border-vertical-spacing', '-webkit-ruby-position',
    '-webkit-tap-highlight-color', '-webkit-text-combine',
  ]);
  /// Значение наследуемого свойства: ближайший предок, который его назвал.
  const __inheritedValue = (el, prop) => {
    let own = el && el.nodeType === ELEMENT_NODE ? __passInherit.get(el) : null;
    if (own) {
      const hit = own.get(prop);
      if (hit !== undefined) return hit;
    }
    let out = null;
    for (let e = el && el.parentNode; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
      const raw = __cascadeFor(e).get(prop);
      if (raw != null) { out = __resolveLength(raw, prop, __usedFontSize(e), e); break; }
    }
    if (el && el.nodeType === ELEMENT_NODE) {
      if (!own) { own = new Map(); __passInherit.set(el, own); }
      own.set(prop, out);
    }
    return out;
  };

  // Сокращённые свойства. В вычисленном стиле браузер их не показывает вовсе
  // — только длинные, — а значение раскладывает по ним сам. Мы же клали в
  // ответ и само сокращение (лишнее имя в перечислении), и оставляли длинные
  // при начальных значениях: `background: blue` не давало `background-color`,
  // `border: 2px solid red` — ни цвета, ни стиля.
  const CS_SIDES = ['top', 'right', 'bottom', 'left'];
  const __ptIsColour = (t) => !!(globalThis.__pt_cssColour && globalThis.__pt_cssColour(t))
    || /^(currentcolor|transparent)$/i.test(t)
    || /^(color|lab|lch|oklab|oklch|color-mix|light-dark)\(/i.test(t);
  const CS_BORDER_STYLES = new Set(['none', 'hidden', 'dotted', 'dashed', 'solid', 'double',
    'groove', 'ridge', 'inset', 'outset']);
  const CS_WIDTH_WORDS = { thin: '1px', medium: '3px', thick: '5px' };
  // Разбиение по пробелам верхнего уровня: `rgba(1, 2, 3, .4) solid 1px` —
  // три куска, а не семь.
  const __ptCssParts = (v) => {
    const out = [];
    let depth = 0, cur = '';
    for (const ch of String(v)) {
      if (ch === '(') depth++;
      if (ch === ')') depth--;
      if (/\s/.test(ch) && depth === 0) { if (cur) out.push(cur); cur = ''; continue; }
      cur += ch;
    }
    if (cur) out.push(cur);
    return out;
  };
  const __ptFourWay = (name, value) => {
    const parts = __ptCssParts(value);
    if (!parts.length) return [];
    const pick = [0, 1, 2, 3].map((i) => parts[[0, 0, 0, 0][i] === 0 ? Math.min(i, parts.length - 1) : i]);
    const order = parts.length === 1 ? [parts[0], parts[0], parts[0], parts[0]]
      : parts.length === 2 ? [parts[0], parts[1], parts[0], parts[1]]
      : parts.length === 3 ? [parts[0], parts[1], parts[2], parts[1]]
      : [parts[0], parts[1], parts[2], parts[3]];
    void pick;
    return CS_SIDES.map((side, i) => [name.replace('*', side), order[i]]);
  };
  // Возвращает пары «длинное свойство — значение» или null, если это не
  // сокращение.
  const __ptExpand = (prop, value) => {
    const v = String(value).trim();
    const parts = __ptCssParts(v);
    const out = [];
    const borderSide = /^border-(top|right|bottom|left|block-start|block-end|inline-start|inline-end)$/.exec(prop);
    if (prop === 'border' || borderSide) {
      const sides = borderSide ? [borderSide[1]] : CS_SIDES;
      let width = 'medium', style = 'none', colour = 'currentcolor';
      for (const t of parts) {
        const low = t.toLowerCase();
        if (CS_BORDER_STYLES.has(low)) style = low;
        else if (CS_WIDTH_WORDS[low] || /^[\d.]/.test(low)) width = CS_WIDTH_WORDS[low] || t;
        else if (__ptIsColour(t)) colour = t;
      }
      if (style === 'none' || style === 'hidden') width = '0px';
      for (const side of sides) {
        out.push(['border-' + side + '-width', width === 'medium' ? '3px' : width]);
        out.push(['border-' + side + '-style', style]);
        out.push(['border-' + side + '-color', colour]);
      }
      return out;
    }
    if (prop === 'border-width' || prop === 'border-style' || prop === 'border-color') {
      const kind = prop.slice('border-'.length);
      return __ptFourWay('border-*-' + kind, v);
    }
    if (prop === 'margin' || prop === 'padding') return __ptFourWay(prop + '-*', v);
    if (prop === 'inset') {
      const four = __ptFourWay('*', v);
      return CS_SIDES.map((side, i) => [side, four[i][1]]);
    }
    if (prop === 'border-radius') {
      const corners = ['top-left', 'top-right', 'bottom-right', 'bottom-left'];
      const round = v.split('/')[0].trim();
      const p = __ptCssParts(round);
      const order = p.length === 1 ? [p[0], p[0], p[0], p[0]]
        : p.length === 2 ? [p[0], p[1], p[0], p[1]]
        : p.length === 3 ? [p[0], p[1], p[2], p[1]]
        : [p[0], p[1], p[2], p[3]];
      return corners.map((c, i) => ['border-' + c + '-radius', order[i]]);
    }
    if (prop === 'background') {
      let colour = null, image = null;
      for (const t of parts) {
        if (/^(url|linear-gradient|radial-gradient|conic-gradient|image-set)\(/i.test(t)) image = t;
        else if (__ptIsColour(t)) colour = t;
      }
      if (colour) out.push(['background-color', colour]);
      if (image) out.push(['background-image', image]);
      if (!out.length) return [];
      return out;
    }
    if (prop === 'outline') {
      let width = 'medium', style = 'none', colour = 'currentcolor';
      for (const t of parts) {
        const low = t.toLowerCase();
        if (CS_BORDER_STYLES.has(low) || low === 'auto') style = low;
        else if (CS_WIDTH_WORDS[low] || /^[\d.]/.test(low)) width = CS_WIDTH_WORDS[low] || t;
        else if (__ptIsColour(t)) colour = t;
      }
      return [['outline-width', width === 'medium' ? '3px' : width],
              ['outline-style', style], ['outline-color', colour]];
    }
    if (prop === 'font') {
      // `font: italic small-caps bold 14px/1.5 Georgia, serif`
      const m = /(^|\s)((?:[\d.]+[a-z%]*|smaller|larger|x?x-(?:small|large)|small|medium|large))(?:\s*\/\s*([^\s]+))?\s+(.+)$/i.exec(v);
      if (!m) return [];
      const before = v.slice(0, m.index).trim().toLowerCase().split(/\s+/).filter(Boolean);
      for (const w of before) {
        if (w === 'italic' || w === 'oblique') out.push(['font-style', w]);
        else if (w === 'small-caps') out.push(['font-variant-caps', w]);
        else if (/^(bold|bolder|lighter|[1-9]00)$/.test(w)) out.push(['font-weight', w === 'bold' ? '700' : w]);
        else if (/^(ultra|extra|semi)?-?(condensed|expanded)$/.test(w)) out.push(['font-stretch', w]);
      }
      out.push(['font-size', m[2]]);
      if (m[3]) out.push(['line-height', m[3]]);
      out.push(['font-family', m[4].trim()]);
      return out;
    }
    if (prop === 'flex') {
      const grow = parts[0] || '0', shrink = parts[1] || '1';
      const basis = parts[2] || (parts.length === 1 && /^[\d.]+$/.test(grow) ? '0%' : 'auto');
      return [['flex-grow', grow], ['flex-shrink', /^[\d.]+$/.test(shrink) ? shrink : '1'],
              ['flex-basis', basis]];
    }
    if (prop === 'gap') {
      const row = parts[0] || 'normal';
      return [['row-gap', row], ['column-gap', parts[1] || row]];
    }
    if (prop === 'overflow') {
      const x = parts[0] || 'visible';
      return [['overflow-x', x], ['overflow-y', parts[1] || x]];
    }
    if (prop === 'place-items' || prop === 'place-content' || prop === 'place-self') {
      const kind = prop.slice('place-'.length);
      const a = parts[0] || 'normal';
      return [['align-' + kind, a], ['justify-' + kind, parts[1] || a]];
    }
    if (prop === 'grid-area') {
      const p = v.split('/').map((x) => x.trim());
      const names = ['grid-row-start', 'grid-column-start', 'grid-row-end', 'grid-column-end'];
      return names.map((n, i) => [n, p[i] || 'auto']).filter(([, x]) => x);
    }
    if (prop === 'grid-row' || prop === 'grid-column') {
      const p = v.split('/').map((x) => x.trim());
      return [[prop + '-start', p[0] || 'auto'], [prop + '-end', p[1] || 'auto']];
    }
    if (prop === 'list-style') {
      for (const t of parts) {
        const low = t.toLowerCase();
        if (low === 'inside' || low === 'outside') out.push(['list-style-position', low]);
        else if (/^(url|linear-gradient|image-set)\(/i.test(t) || low === 'none') out.push(['list-style-image', low === 'none' ? 'none' : t]);
        else out.push(['list-style-type', t]);
      }
      return out;
    }
    if (prop === 'transition') {
      // Первый слой: браузер печатает списки по слоям, а на странице почти
      // всегда один.
      const layer = v.split(',')[0].trim();
      const p = __ptCssParts(layer);
      const times = p.filter((x) => /^[\d.]+m?s$/i.test(x));
      const ease = p.find((x) => /^(ease|ease-in|ease-out|ease-in-out|linear|step-start|step-end|cubic-bezier\(|steps\()/i.test(x));
      const name = p.find((x) => !/^[\d.]+m?s$/i.test(x) && x !== ease);
      const secs = (t) => (/ms$/i.test(t) ? (parseFloat(t) / 1000) : parseFloat(t)) + 's';
      return [['transition-property', name || 'all'],
              ['transition-duration', times[0] ? secs(times[0]) : '0s'],
              ['transition-timing-function', ease || 'ease'],
              ['transition-delay', times[1] ? secs(times[1]) : '0s']];
    }
    if (prop === 'text-decoration') {
      for (const t of parts) {
        const low = t.toLowerCase();
        if (/^(none|underline|overline|line-through|blink)$/.test(low)) out.push(['text-decoration-line', low]);
        else if (/^(solid|double|dotted|dashed|wavy)$/.test(low)) out.push(['text-decoration-style', low]);
        else if (__ptIsColour(t)) out.push(['text-decoration-color', t]);
        else out.push(['text-decoration-thickness', t]);
      }
      return out;
    }
    return null;
  };
  // Цвет, унаследованный от `color`: у этих свойств начальное значение —
  // `currentColor`, и браузер печатает в них цвет самого элемента.
  const CS_CURRENT_COLOUR = ['caret-color', 'column-rule-color', 'row-rule-color', 'outline-color',
    'text-decoration-color', 'text-emphasis-color', '-webkit-text-fill-color',
    '-webkit-text-stroke-color', 'border-top-color', 'border-right-color',
    'border-bottom-color', 'border-left-color', 'border-block-start-color',
    'border-block-end-color', 'border-inline-start-color', 'border-inline-end-color'];
  // Логические имена браузер печатает теми же значениями, что и физические.
  const CS_LOGICAL = [
    ['border-block-start-color', 'border-top-color'], ['border-block-end-color', 'border-bottom-color'],
    ['border-inline-start-color', 'border-left-color'], ['border-inline-end-color', 'border-right-color'],
    ['border-block-start-style', 'border-top-style'], ['border-block-end-style', 'border-bottom-style'],
    ['border-inline-start-style', 'border-left-style'], ['border-inline-end-style', 'border-right-style'],
    ['border-block-start-width', 'border-top-width'], ['border-block-end-width', 'border-bottom-width'],
    ['border-inline-start-width', 'border-left-width'], ['border-inline-end-width', 'border-right-width'],
    ['margin-block-start', 'margin-top'], ['margin-block-end', 'margin-bottom'],
    ['margin-inline-start', 'margin-left'], ['margin-inline-end', 'margin-right'],
    ['padding-block-start', 'padding-top'], ['padding-block-end', 'padding-bottom'],
    ['padding-inline-start', 'padding-left'], ['padding-inline-end', 'padding-right'],
    ['inset-block-start', 'top'], ['inset-block-end', 'bottom'],
    ['inset-inline-start', 'left'], ['inset-inline-end', 'right'],
    ['inline-size', 'width'], ['block-size', 'height'],
    ['overflow-block', 'overflow-y'], ['overflow-inline', 'overflow-x'],
    ['border-start-start-radius', 'border-top-left-radius'],
    ['border-start-end-radius', 'border-top-right-radius'],
    ['border-end-start-radius', 'border-bottom-left-radius'],
    ['border-end-end-radius', 'border-bottom-right-radius'],
    ['min-inline-size', 'min-width'], ['min-block-size', 'min-height'],
    ['max-inline-size', 'max-width'], ['max-block-size', 'max-height'],
  ];

  // Какие свойства движок знает: `CSS.supports` у браузера отвечает `false`
  // на выдуманное имя, а у нас отвечал `true` на что угодно с двоеточием.
  try {
    const known = new Set(CS_ORDER);
    for (const name of CSS_PROPS) {
      const plain = name.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase()).toLowerCase();
      known.add(plain);
      if (/^(webkit|moz|ms|o)-/.test(plain)) known.add('-' + plain);
    }
    Object.defineProperty(globalThis, '__pt_cssKnown', {
      value: (name) => known.has(String(name).trim().toLowerCase()),
      enumerable: false, configurable: true, writable: true,
    });
  } catch (e) {}

  // Вычисленный стиль дорог: тысяча двести свойств, каскад, наследование и
  // раскладка. Страница спрашивает его десятками раз подряд, и между
  // вопросами ничего не меняется — держим готовый ответ до первой правки
  // дерева.
  const __computedCache = new WeakMap();

  // В плоском дереве ли узел: дитя хозяина теневого корня попадает туда только
  // через слот с тем же именем; остальные хозяин прячет, и стиля у них нет.
  function __inFlatTree(el) {
    let n = el;
    for (let guard = 0; n && guard < 10000; guard++) {
      const p = n.parentNode;
      // Корень — документ (какой именно, проверяет вызывающий по ownerDocument:
      // у реалма корень дерева и глобальный `document` — разные объекты).
      if (!p) return n.nodeType === 9;
      if (p.nodeType === ELEMENT_NODE && p.__ptShadow) {
        const sr = p.__ptShadow;
        const want = n.nodeType === ELEMENT_NODE ? (__ptGetA(n, 'slot') || '') : '';
        let slot = null;
        try { __walkTree(sr, (x) => { if (!slot && x.nodeType === ELEMENT_NODE && x.__ptLocal === 'slot' && (__ptGetA(x, 'name') || '') === want) slot = x; }); } catch (e) {}
        if (!slot) return false;
        n = slot;
        continue;
      }
      if (p.nodeType === 11 && p.__ptHost) { n = p.__ptHost; continue; }
      n = p;
    }
    return false;
  }
  globalThis.__pt_inFlatTree = __inFlatTree;

  globalThis.getComputedStyle = (el, pseudo) => {
    if (el && !pseudo && el.nodeType === ELEMENT_NODE) {
      __relayout();
      const hit = __computedCache.get(el);
      if (hit && hit.at === __layoutBuilt) return hit.style;
    }
    const map = new Map();
    // У элемента вне отрисованного дерева вычисленного стиля нет: браузер
    // отдаёт пустую строку на каждое свойство и `length` ноль. Мы отвечали
    // значениями по умолчанию — то есть утверждали, что оторванный `<div>`
    // блочный и чёрный, чего браузер про него не говорит. Проверяется одной
    // строкой: создать элемент и спросить его `display`.
    const connected = !!(el && el.nodeType === ELEMENT_NODE && el.isConnected);
    // Документ без окна (DOMParser, createHTMLDocument): стиль не считается
    // вовсе — пусто и длина ноль. Узел в окне, но вне плоского дерева (дитя
    // хозяина теневого корня без слота): имена есть, значения пусты.
    const inView = connected && (!el.ownerDocument || el.ownerDocument === document || !!el.ownerDocument.defaultView);
    if (!connected || !inView) {
      for (const k of CS_ORDER) map.set(k, '');
      return __makeComputed(map, []);
    }
    if (!__inFlatTree(el)) {
      for (const k of CS_ORDER) map.set(k, '');
      const names = [...map.keys()];
      __addShorthands(map);
      return __makeComputed(map, names);
    }
    for (const k of CS_ORDER) map.set(k, CS_BASE[k]);
    const tag = (el && el.localName) || 'div';
    if (CS_DISPLAY[tag] === 'inline' || CS_INLINE) {
      const inlineish = CS_DISPLAY[tag] === 'inline';
      if (inlineish) for (const [k, v] of Object.entries(CS_INLINE)) map.set(k, v);
    }
    if (CS_REPLACED_TAGS.has(tag)) for (const [k, v] of Object.entries(CS_REPLACED)) map.set(k, v);
    if (CS_DISPLAY[tag]) map.set('display', CS_DISPLAY[tag]);
    if (UA_BIDI[tag]) map.set('unicode-bidi', UA_BIDI[tag]);
    // Заявленное автором поверх умолчаний, потом — использованные размеры.
    // Автор — это и таблицы стилей, а не только атрибут `style`: элемент с
    // `width: 200px` в таблице отвечал шириной окна, противореча CSS страницы.
    try {
      __relayout();
      const cascade = el ? __cascadeFor(el) : new Map();
      const fs = el ? __usedFontSize(el) : 16;
      // Сначала унаследованное от предков, потом своё поверх.
      for (const prop of CSS_INHERITED) {
        if (cascade.has(prop)) continue;
        const v = __inheritedValue(el, prop);
        if (v == null) continue;
        const pairs = __ptExpand(prop, v);
        if (pairs) { for (const [k, val] of pairs) if (map.has(k)) map.set(k, val); continue; }
        if (map.has(prop)) map.set(prop, v);
      }
      if (UA_BOLD.has(tag)) map.set('font-weight', '700');
      // Моноширинное семейство браузер задаёт своей таблицей, а она сильнее
      // наследования: `<pre>` внутри тела с заданным шрифтом всё равно
      // набирается моноширинным.
      if (UA_MONO.has(tag)) map.set('font-family', 'monospace');
      // Только длинные имена: сокращений в вычисленном стиле браузер не
      // показывает, но раскладывает их значения по длинным сам.
      const put = (k, raw) => {
        if (!map.has(k)) return;
        map.set(k, __resolveLength(String(raw).trim(), k, fs, el));
      };
      const written = new Set();
      for (const [n, raw] of cascade) {
        const v = __resolveLength(raw, n, fs, el);
        const pairs = __ptExpand(n, v);
        if (pairs) {
          for (const [k, val] of pairs) { put(k, val); written.add(k); }
          continue;
        }
        put(n, v);
        written.add(n);
      }
      // Поля от таблицы стилей самого браузера: автор их перебивает, но там,
      // где автор молчит, браузер печатает своё — у тела страницы восемь
      // пикселей, у абзаца кегль, у заголовка доля кегля.
      {
        const q = (v) => (Math.round(v * 1e4) / 1e4) + 'px';
        const uam = __uaMargin(tag, fs);
        if (uam) {
          for (const [k, v] of [['margin-top', uam[0]], ['margin-bottom', uam[0]],
                                ['margin-left', uam[1]], ['margin-right', uam[1]]]) {
            if (!written.has(k) && map.has(k)) map.set(k, q(v));
          }
        }
        // `auto` браузер в вычисленном стиле не печатает: он отвечает тем
        // полем, которое получилось на раскладке — у блока по центру это
        // половина свободного места.
        const ab = __boxOf(el);
        if (ab) {
          for (const [k, v] of [['margin-top', ab.mt], ['margin-bottom', ab.mb],
                                ['margin-left', ab.ml], ['margin-right', ab.mr]]) {
            if (v != null && /^auto$/i.test(String(map.get(k) || ''))) map.set(k, q(v));
          }
        }
      }
      // Преобразование браузер печатает матрицей: `matrix(1.001, 0, 0, 1.001, 0, 0)`.
      {
        const tr = map.get('transform');
        if (tr && tr !== 'none') {
          const M = __parseTransform(tr);
          if (M) map.set('transform', 'matrix(' + M.map(__cssNum1).join(', ') + ')');
        }
      }
      // Цвет по записи браузера: всякая запись sRGB приводится к `rgb(…)`.
      for (const k of map.keys()) {
        if (k !== 'color' && !k.endsWith('-color')) continue;
        const norm = globalThis.__pt_cssColour && globalThis.__pt_cssColour(map.get(k));
        if (norm) map.set(k, norm);
      }
      // `currentColor` — начальное значение у целого ряда свойств: браузер
      // печатает в них цвет самого элемента.
      const own = map.get('color');
      if (own) {
        for (const k of CS_CURRENT_COLOUR) {
          if (!map.has(k)) continue;
          const cur = map.get(k);
          if (!written.has(k) || /^currentcolor$/i.test(String(cur))) map.set(k, own);
        }
      }
      // Логические имена повторяют физические.
      for (const [logical, physical] of CS_LOGICAL) {
        if (map.has(logical) && map.has(physical) && !written.has(logical)) {
          map.set(logical, map.get(physical));
        }
      }
      // Ребёнок гибкого контейнера: браузер делает его блочным и меняет
      // начальный минимум на `auto`.
      try {
        const parent = el.parentNode;
        const pd = parent && parent.nodeType === ELEMENT_NODE
          ? String(__cascadeFor(parent).get('display') || CS_DISPLAY[parent.localName] || '')
          : '';
        if (/^(flex|inline-flex|grid|inline-grid)$/.test(pd)) {
          if (!written.has('display') && /^(inline|inline-block)$/.test(String(map.get('display')))) {
            map.set('display', 'block');
          }
          for (const k of ['min-width', 'min-height', 'min-inline-size', 'min-block-size']) {
            if (!written.has(k) && map.has(k)) map.set(k, 'auto');
          }
        }
      } catch (e) {}
      // Тень браузер печатает по-своему: сперва цвет, потом четыре длины с
      // единицами, и `inset` в конце.
      {
        const sh = String(map.get('box-shadow') || '');
        // Вычисленный стиль печатает все четыре длины, даже если автор написал
        // две: браузер дописывает размытие и разброс нулями.
        if (sh && sh !== 'none') {
          const parts = __ptCssParts(sh);
          let colour = null, inset = false;
          const lens = [];
          for (const t of parts) {
            if (/^inset$/i.test(t)) { inset = true; continue; }
            if (/^[-\d.]/.test(t)) { lens.push(t); continue; }
            const norm = globalThis.__pt_cssColour && globalThis.__pt_cssColour(t);
            if (norm) colour = norm;
          }
          while (lens.length < 4) lens.push('0px');
          const px = (x) => (/^[-\d.]+$/.test(x) ? x + 'px' : x);
          map.set('box-shadow', [colour || map.get('color'), px(lens[0]), px(lens[1]), px(lens[2]), px(lens[3])]
            .join(' ') + (inset ? ' inset' : ''));
        }
      }
      // Множитель межстрочного браузер печатает уже в пикселях.
      const lh = String(map.get('line-height') || '');
      if (/^[\d.]+$/.test(lh)) {
        const px = parseFloat(lh) * parseFloat(map.get('font-size')) || 0;
        map.set('line-height', (Math.round(px * 1e4) / 1e4) + 'px');
      }
      // Ссылка: у браузера свой стиль по умолчанию, и он виден в вычисленном.
      if (el.localName === 'a' && __ptHasA(el, 'href')) {
        if (!written.has('cursor')) map.set('cursor', 'pointer');
        if (!written.has('text-decoration-line')) map.set('text-decoration-line', 'underline');
      }
      // Сокращения, которые браузер всё же печатает, собираются из длинных.
      {
        const line = map.get('text-decoration-line');
        if (map.has('text-decoration')) {
          let td = line || 'none';
          const st = map.get('text-decoration-style');
          if (st && st !== 'solid') td += ' ' + st;
          const col = map.get('text-decoration-color');
          if (col && col !== own && written.has('text-decoration-color')) td += ' ' + col;
          map.set('text-decoration', td);
        }
        if (map.has('-webkit-text-decorations-in-effect')) {
          map.set('-webkit-text-decorations-in-effect', line && line !== 'none' ? line : 'none');
        }
        if (map.has('font-variant')) {
          const caps = map.get('font-variant-caps');
          map.set('font-variant', caps && caps !== 'normal' ? caps : 'normal');
        }
      }
      if (el) map.set('font-size', __usedFontSize(el) + 'px');
    } catch (e) {}
    try {
      if (el && el.nodeType === ELEMENT_NODE) {
        if (__isUnboxed(el)) map.set('display', 'none');
        const b = __boxOf(el);
        if (b) {
          // Браузер называет здесь поле содержимого: у элемента с рамкой и
          // отступами `width` — это его `width` из CSS, а не внешний размер.
          // Браузер печатает вычисленную длину с четырьмя знаками после
          // запятой: `72.2656px`, не `72.265625px`.
          const q = (v) => {
            const r = Math.round(v * 1e4) / 1e4;
            return (Number.isInteger(r) ? r : parseFloat(r.toFixed(4))) + 'px';
          };
          // При `border-box` — вместе с полями и рамкой, как и названо в CSS.
          const outer = map.get('box-sizing') === 'border-box';
          const w = outer ? b.w : b.cw, h = outer ? b.h : b.ch;
          map.set('width', q(w)); map.set('height', q(h));
          map.set('inline-size', q(w)); map.set('block-size', q(h));
          map.set('perspective-origin', q(b.w / 2) + ' ' + q(b.h / 2));
          map.set('transform-origin', q(b.w / 2) + ' ' + q(b.h / 2));
        }
      }
    } catch (e) {}
    // Перечисляются только длинные свойства: сокращения читаются, но в
    // `length` и в нумерованные имена не попадают, как и в браузере.
    // Ребёнок гибкого контейнера и сетки, а ещё вынутый из потока
    // (`absolute`, `fixed`, `float`) и корень — блочные, как бы их ни
    // объявили: браузер печатает `grid` там, где написано `inline-grid`.
    if (el && el.nodeType === ELEMENT_NODE) {
      const BLOCKIFY = { inline: 'block', 'inline-block': 'block', 'inline-flex': 'flex', 'inline-grid': 'grid', 'inline-table': 'table', 'inline-flow-root': 'flow-root', 'list-item': null };
      const d = map.get('display');
      const to = BLOCKIFY[d];
      if (to) {
        let why = el.ownerDocument && el === el.ownerDocument.documentElement;
        const pos = map.get('position');
        if (pos === 'absolute' || pos === 'fixed') why = true;
        if (map.get('float') && map.get('float') !== 'none') why = true;
        let p = el.parentNode;
        while (!why && p && p.nodeType === ELEMENT_NODE) {
          const pd = String(__cascadeFor(p).get('display') || CS_DISPLAY[p.localName] || '').trim().toLowerCase();
          if (pd === 'contents') { p = p.parentNode; continue; }
          if (/^(inline-)?(flex|grid)$/.test(pd)) why = true;
          break;
        }
        if (why) map.set('display', to);
      }
    }
    // Числа в вычисленном стиле печатаются шестью значащими цифрами, как и
    // в объявлении: `138.828125px` → `138.828px`.
    for (const k of map.keys()) {
      const v = map.get(k);
      if (typeof v === 'string' && v && /\d/.test(v) && !(k.charCodeAt(0) === 45 && k.charCodeAt(1) === 45)) {
        try { map.set(k, __cssNumbers(v)); } catch (e) {}
      }
    }
    const names = [...map.keys()];
    __addShorthands(map);
    // Собственные свойства читаются `getPropertyValue('--имя')`, но в
    // перечислении не стоят.
    if (el && el.nodeType === ELEMENT_NODE) {
      const vars = __passCustom.get(el);
      if (vars) for (const k in vars) if (typeof vars[k] === 'string') map.set(k, vars[k]);
    }
    const made = __makeComputed(map, names);
    if (el && !pseudo && el.nodeType === ELEMENT_NODE) {
      try { __computedCache.set(el, { at: __layoutBuilt, style: made }); } catch (e) {}
    }
    return made;
  };

  /// Объявление вычисленного стиля. `names` пуст, когда элемент не отрисован:
  /// тогда у объекта нет числовых свойств и `length` равен нулю, но имена в
  /// camelCase на месте — их семьсот сорок пять и у отрисованного, и у нет.
  // Сокращённые свойства вычисленного стиля. Браузер отвечает на них
  // собранным значением, у нас они были пустыми строками — а страница, которая
  // перечисляет весь стиль и складывает пары «имя: значение», недосчитывалась
  // двух с половиной сотен значений.
  //
  // Собирается из длинных свойств по правилам записи CSS. Псевдонимы
  // `-webkit-*` зеркалят обычное свойство. Остальное — начальные значения,
  // снятые с Chrome: у этих сокращений нет длинных свойств, которые мы ведём.
  const SH_ALIAS = {"webkit-align-content": "align-content", "webkit-align-items": "align-items", "webkit-align-self": "align-self", "webkit-animation": "animation", "webkit-animation-delay": "animation-delay", "webkit-animation-direction": "animation-direction", "webkit-animation-duration": "animation-duration", "webkit-animation-fill-mode": "animation-fill-mode", "webkit-animation-iteration-count": "animation-iteration-count", "webkit-animation-name": "animation-name", "webkit-animation-play-state": "animation-play-state", "webkit-animation-timing-function": "animation-timing-function", "webkit-app-region": "app-region", "webkit-appearance": "appearance", "webkit-backface-visibility": "backface-visibility", "webkit-background-clip": "background-clip", "webkit-background-origin": "background-origin", "webkit-background-size": "background-size", "webkit-border-bottom-left-radius": "border-bottom-left-radius", "webkit-border-bottom-right-radius": "border-bottom-right-radius", "webkit-border-image": "border-image", "webkit-border-radius": "border-radius", "webkit-border-top-left-radius": "border-top-left-radius", "webkit-border-top-right-radius": "border-top-right-radius", "webkit-box-decoration-break": "box-decoration-break", "webkit-box-shadow": "box-shadow", "webkit-box-sizing": "box-sizing", "webkit-clip-path": "clip-path", "webkit-column-count": "column-count", "webkit-column-gap": "column-gap", "webkit-column-rule": "column-rule", "webkit-column-rule-color": "column-rule-color", "webkit-column-rule-style": "column-rule-style", "webkit-column-rule-width": "column-rule-width", "webkit-column-span": "column-span", "webkit-column-width": "column-width", "webkit-columns": "columns", "webkit-filter": "filter", "webkit-flex": "flex", "webkit-flex-basis": "flex-basis", "webkit-flex-direction": "flex-direction", "webkit-flex-flow": "flex-flow", "webkit-flex-grow": "flex-grow", "webkit-flex-shrink": "flex-shrink", "webkit-flex-wrap": "flex-wrap", "webkit-font-feature-settings": "font-feature-settings", "webkit-hyphenate-character": "hyphenate-character", "webkit-justify-content": "justify-content", "webkit-line-break": "line-break", "webkit-mask": "mask", "webkit-mask-clip": "mask-clip", "webkit-mask-composite": "mask-composite", "webkit-mask-image": "mask-image", "webkit-mask-origin": "mask-origin", "webkit-mask-position": "mask-position", "webkit-mask-repeat": "mask-repeat", "webkit-mask-size": "mask-size", "webkit-opacity": "opacity", "webkit-order": "order", "webkit-perspective": "perspective", "webkit-perspective-origin": "perspective-origin", "webkit-print-color-adjust": "print-color-adjust", "webkit-shape-image-threshold": "shape-image-threshold", "webkit-shape-margin": "shape-margin", "webkit-shape-outside": "shape-outside", "webkit-text-emphasis": "text-emphasis", "webkit-text-emphasis-color": "text-emphasis-color", "webkit-text-emphasis-position": "text-emphasis-position", "webkit-text-emphasis-style": "text-emphasis-style", "webkit-text-size-adjust": "text-size-adjust", "webkit-transform": "transform", "webkit-transform-origin": "transform-origin", "webkit-transform-style": "transform-style", "webkit-transition": "transition", "webkit-transition-delay": "transition-delay", "webkit-transition-duration": "transition-duration", "webkit-transition-property": "transition-property", "webkit-transition-timing-function": "transition-timing-function", "webkit-user-select": "user-select", "webkit-writing-mode": "writing-mode"};
  const SH_CONST = {"animation-range": "normal", "border-image": "none", "border-spacing": "0px", "column-rule-inset": "0px", "column-rule-inset-cap": "0px", "column-rule-inset-end": "0px", "column-rule-inset-junction": "0px", "column-rule-inset-start": "0px", "columns": "auto", "container": "none", "corner-block-end-shape": "round", "corner-block-start-shape": "round", "corner-bottom-shape": "round", "corner-inline-end-shape": "round", "corner-inline-start-shape": "round", "corner-left-shape": "round", "corner-right-shape": "round", "corner-shape": "round", "corner-top-shape": "round", "interest-delay": "normal", "marker": "none", "mask": "none", "offset": "none 0px auto 0deg", "page": "auto", "position-try": "none", "row-rule": "3px rgb(0, 0, 0)", "row-rule-inset": "0px", "row-rule-inset-cap": "0px", "row-rule-inset-end": "0px", "row-rule-inset-junction": "0px", "row-rule-inset-start": "0px", "rule": "3px rgb(0, 0, 0)", "rule-break": "normal", "rule-color": "rgb(0, 0, 0)", "rule-inset": "0px", "rule-inset-cap": "0px", "rule-inset-end": "0px", "rule-inset-junction": "0px", "rule-inset-start": "0px", "rule-style": "none", "rule-visibility-items": "normal", "rule-width": "3px", "scroll-timeline": "none", "text-box": "normal", "timeline-trigger": "none", "timeline-trigger-activation-range": "normal", "timeline-trigger-active-range": "auto", "view-timeline": "none", "webkit-border-after": "0px none rgb(0, 0, 0)", "webkit-border-after-color": "rgb(0, 0, 0)", "webkit-border-after-style": "none", "webkit-border-after-width": "0px", "webkit-border-before": "0px none rgb(0, 0, 0)", "webkit-border-before-color": "rgb(0, 0, 0)", "webkit-border-before-style": "none", "webkit-border-before-width": "0px", "webkit-border-end": "0px none rgb(0, 0, 0)", "webkit-border-end-color": "rgb(0, 0, 0)", "webkit-border-end-style": "none", "webkit-border-end-width": "0px", "webkit-border-horizontal-spacing": "0px", "webkit-border-start": "0px none rgb(0, 0, 0)", "webkit-border-start-color": "rgb(0, 0, 0)", "webkit-border-start-style": "none", "webkit-border-start-width": "0px", "webkit-border-vertical-spacing": "0px", "webkit-box-align": "stretch", "webkit-box-direction": "normal", "webkit-box-flex": "0", "webkit-box-ordinal-group": "1", "webkit-box-orient": "horizontal", "webkit-box-pack": "start", "webkit-box-reflect": "none", "webkit-column-break-after": "auto", "webkit-column-break-before": "auto", "webkit-column-break-inside": "auto", "webkit-font-smoothing": "auto", "webkit-line-clamp": "none", "webkit-locale": "\"en\"", "webkit-logical-height": "0px", "webkit-logical-width": "925px", "webkit-margin-after": "0px", "webkit-margin-before": "0px", "webkit-margin-end": "0px", "webkit-margin-start": "0px", "webkit-mask-box-image": "none", "webkit-mask-box-image-outset": "0", "webkit-mask-box-image-repeat": "stretch", "webkit-mask-box-image-slice": "0 fill", "webkit-mask-box-image-source": "none", "webkit-mask-box-image-width": "auto", "webkit-mask-position-x": "0%", "webkit-mask-position-y": "0%", "webkit-max-logical-height": "none", "webkit-max-logical-width": "none", "webkit-min-logical-height": "0px", "webkit-min-logical-width": "0px", "webkit-padding-after": "0px", "webkit-padding-before": "0px", "webkit-padding-end": "0px", "webkit-padding-start": "0px", "webkit-rtl-ordering": "logical", "webkit-ruby-position": "before", "webkit-tap-highlight-color": "rgba(0, 0, 0, 0.18)", "webkit-text-combine": "none", "webkit-text-decorations-in-effect": "none", "webkit-text-fill-color": "rgb(0, 0, 0)", "webkit-text-orientation": "vertical-right", "webkit-text-security": "none", "webkit-text-stroke": "0px rgb(0, 0, 0)", "webkit-text-stroke-color": "rgb(0, 0, 0)", "webkit-text-stroke-width": "0px", "webkit-user-drag": "auto", "webkit-user-modify": "read-only"};
  const __addShorthands = (map) => {
    const g = (k) => map.get(k) || '';
    const set = (k, v) => { if (v !== '' && v != null) map.set(k, v); };
    // Четыре стороны сворачиваются, пока значения совпадают.
    const four = (t, r, b, l) => {
      if (!t) return '';
      if (t === r && r === b && b === l) return t;
      if (t === b && r === l) return t + ' ' + r;
      if (r === l) return t + ' ' + r + ' ' + b;
      return t + ' ' + r + ' ' + b + ' ' + l;
    };
    const two = (a, b) => (a === b ? a : (a && b ? a + ' ' + b : a || b));
    const box = (name, suffix) => four(g(name + '-top' + suffix), g(name + '-right' + suffix),
      g(name + '-bottom' + suffix), g(name + '-left' + suffix));
    set('margin', box('margin', ''));
    set('padding', box('padding', ''));
    set('scroll-margin', box('scroll-margin', ''));
    set('scroll-padding', box('scroll-padding', ''));
    set('inset', four(g('top'), g('right'), g('bottom'), g('left')));
    set('border-width', box('border', '-width'));
    set('border-style', box('border', '-style'));
    set('border-color', box('border', '-color'));
    set('border-radius', four(g('border-top-left-radius'), g('border-top-right-radius'),
      g('border-bottom-right-radius'), g('border-bottom-left-radius')));
    for (const [sh, base] of [['margin-block', 'margin-block'], ['margin-inline', 'margin-inline'],
      ['padding-block', 'padding-block'], ['padding-inline', 'padding-inline'],
      ['inset-block', 'inset-block'], ['inset-inline', 'inset-inline'],
      ['scroll-margin-block', 'scroll-margin-block'], ['scroll-margin-inline', 'scroll-margin-inline'],
      ['scroll-padding-block', 'scroll-padding-block'], ['scroll-padding-inline', 'scroll-padding-inline'],
      ['border-block-width', 'border-block'], ['border-inline-width', 'border-inline'],
      ['border-block-style', 'border-block'], ['border-inline-style', 'border-inline'],
      ['border-block-color', 'border-block'], ['border-inline-color', 'border-inline']]) {
      const tail = sh.slice(base.length);
      set(sh, two(g(base + '-start' + tail), g(base + '-end' + tail)));
    }
    // Рамка: ширина, стиль, цвет — и только когда все стороны согласны.
    const edge = (p) => {
      const w = g(p + '-width'), s = g(p + '-style'), c = g(p + '-color');
      return w && s && c ? w + ' ' + s + ' ' + c : '';
    };
    for (const p of ['border-top', 'border-right', 'border-bottom', 'border-left',
      'border-block-start', 'border-block-end', 'border-inline-start', 'border-inline-end']) set(p, edge(p));
    set('border-block', edge('border-block-start') === edge('border-block-end') ? edge('border-block-start') : '');
    set('border-inline', edge('border-inline-start') === edge('border-inline-end') ? edge('border-inline-start') : '');
    const bt = edge('border-top');
    set('border', (bt && bt === edge('border-right') && bt === edge('border-bottom') && bt === edge('border-left')) ? bt : '');
    set('column-rule', g('column-rule-width') + ' ' + g('column-rule-color'));
    set('row-rule', g('row-rule-width') + ' ' + g('row-rule-color'));
    // Общая линейка колонок и рядов: браузер печатает её, когда обе совпадают.
    set('rule-width', two(g('row-rule-width'), g('column-rule-width')));
    set('rule-style', two(g('row-rule-style'), g('column-rule-style')));
    set('rule-color', two(g('row-rule-color'), g('column-rule-color')));
    set('rule', g('rule-width') + ' ' + g('rule-color'));
    // Старые вебкитовские имена логических сторон — те же значения.
    for (const [old_, now] of [['webkit-border-before', 'border-block-start'],
      ['webkit-border-after', 'border-block-end'],
      ['webkit-border-start', 'border-inline-start'],
      ['webkit-border-end', 'border-inline-end'],
      ['webkit-margin-before', 'margin-block-start'], ['webkit-margin-after', 'margin-block-end'],
      ['webkit-margin-start', 'margin-inline-start'], ['webkit-margin-end', 'margin-inline-end'],
      ['webkit-padding-before', 'padding-block-start'], ['webkit-padding-after', 'padding-block-end'],
      ['webkit-padding-start', 'padding-inline-start'], ['webkit-padding-end', 'padding-inline-end'],
      ['webkit-logical-width', 'inline-size'], ['webkit-logical-height', 'block-size'],
      ['webkit-min-logical-width', 'min-inline-size'], ['webkit-min-logical-height', 'min-block-size'],
      ['webkit-max-logical-width', 'max-inline-size'], ['webkit-max-logical-height', 'max-block-size'],
      ['webkit-perspective-origin', 'perspective-origin'],
      ['webkit-transform-origin', 'transform-origin']]) {
      map.set(old_, g(now));
      for (const tail of ['-width', '-style', '-color']) if (g(now + tail)) map.set(old_ + tail, g(now + tail));
    }
    // Обводка текста: ширина и цвет вместе, как её печатает браузер.
    map.set('webkit-text-stroke-color', g('-webkit-text-stroke-color'));
    map.set('webkit-text-stroke-width', g('-webkit-text-stroke-width'));
    map.set('webkit-text-stroke', g('-webkit-text-stroke-width') + ' ' + g('-webkit-text-stroke-color'));
    // Обвод браузер пишет цветом, стилем и шириной — именно в этом порядке.
    set('outline', g('outline-color') + ' ' + g('outline-style') + ' ' + g('outline-width'));
    set('background', g('background-color') + ' ' + g('background-image') + ' ' + g('background-repeat') +
      ' ' + g('background-attachment') + ' ' + g('background-position') + ' / ' + g('background-size') +
      ' ' + g('background-origin') + ' ' + g('background-clip'));
    const bp = g('background-position').split(/\s+/);
    set('background-position-x', bp[0] || '');
    set('background-position-y', bp[1] || bp[0] || '');
    set('flex', g('flex-grow') + ' ' + g('flex-shrink') + ' ' + g('flex-basis'));
    set('flex-flow', g('flex-direction') + ' ' + g('flex-wrap'));
    // Шрифт браузер печатает целиком: начертание, капитель, насыщенность,
    // кегль с межстрочным через косую черту и семейство.
    {
      const bits = [];
      if (g('font-style') && g('font-style') !== 'normal') bits.push(g('font-style'));
      if (g('font-variant-caps') && g('font-variant-caps') !== 'normal') bits.push(g('font-variant-caps'));
      if (g('font-weight') && g('font-weight') !== '400') bits.push(g('font-weight'));
      const lh = g('line-height');
      bits.push(lh && lh !== 'normal' ? g('font-size') + ' / ' + lh : g('font-size'));
      bits.push(g('font-family'));
      set('font', bits.filter(Boolean).join(' '));
    }
    set('font-synthesis', ['weight', 'style', 'small-caps']
      .filter((p) => g('font-synthesis-' + p) === 'auto').join(' ') || 'none');
    set('list-style', g('list-style-position') + ' ' + g('list-style-image') + ' ' + g('list-style-type'));
    set('text-emphasis', g('text-emphasis-style') + ' ' + g('text-emphasis-color'));
    set('gap', two(g('row-gap'), g('column-gap')));
    set('grid-gap', two(g('row-gap'), g('column-gap')));
    set('grid-row-gap', g('row-gap'));
    set('grid-column-gap', g('column-gap'));
    set('place-content', two(g('align-content'), g('justify-content')));
    set('place-items', two(g('align-items'), g('justify-items')));
    set('place-self', two(g('align-self'), g('justify-self')));
    // Части сетки браузер разделяет косой чертой, а пустой конец опускает.
    for (const axis of ['row', 'column']) {
      const a = g('grid-' + axis + '-start'), b = g('grid-' + axis + '-end');
      set('grid-' + axis, !b || b === 'auto' || b === a ? a : a + ' / ' + b);
    }
    {
      const quad = [g('grid-row-start'), g('grid-column-start'), g('grid-row-end'), g('grid-column-end')];
      set('grid-area', quad.every((x) => x === 'auto') ? 'auto' : quad.join(' / '));
    }
    set('grid-template', g('grid-template-rows') === 'none' && g('grid-template-columns') === 'none' &&
      g('grid-template-areas') === 'none' ? 'none' : '');
    set('grid', g('grid-template') === 'none'
      ? 'none / none / none / ' + g('grid-auto-flow') + ' / ' + g('grid-auto-rows') + ' / ' + g('grid-auto-columns')
      : '');
    set('overflow', two(g('overflow-x'), g('overflow-y')));
    set('overscroll-behavior', two(g('overscroll-behavior-x'), g('overscroll-behavior-y')));
    set('columns', two(g('column-width'), g('column-count')) === 'auto auto' ? 'auto'
      : two(g('column-width'), g('column-count')));
    set('animation', g('animation-name') === 'none' && g('animation-duration') === '0s' ? 'none' : '');
    // Переход: браузер опускает то, что стоит на своём начальном значении.
    {
      const dur = g('transition-duration'), ease = g('transition-timing-function');
      const delay = g('transition-delay'), prop = g('transition-property');
      set('transition', dur === '0s' && delay === '0s' ? prop
        : [prop && prop !== 'all' ? prop : '', dur,
           ease && ease !== 'ease' ? ease : '', delay && delay !== '0s' ? delay : '']
          .filter(Boolean).join(' '));
    }
    // Пробелы: браузер сводит их к одному слову, когда сочетание известное.
    const wsc = g('white-space-collapse'), twm = g('text-wrap-mode');
    set('white-space', wsc === 'collapse' && twm === 'wrap' ? 'normal'
      : (wsc === 'preserve' && twm === 'nowrap' ? 'pre'
      : (wsc === 'preserve' && twm === 'wrap' ? 'pre-wrap'
      : (wsc === 'preserve-breaks' && twm === 'wrap' ? 'pre-line'
      : (wsc === 'collapse' && twm === 'nowrap' ? 'nowrap' : wsc + ' ' + twm)))));
    set('text-wrap', two(g('text-wrap-mode'), g('text-wrap-style')) === 'wrap auto' ? 'wrap'
      : two(g('text-wrap-mode'), g('text-wrap-style')));
    set('word-wrap', g('overflow-wrap'));
    set('page-break-after', g('break-after'));
    set('page-break-before', g('break-before'));
    set('page-break-inside', g('break-inside'));
    // Постоянные раньше псевдонимов: иначе зеркало ссылается на пустоту.
    for (const k of Object.keys(SH_CONST)) if (!map.has(k)) map.set(k, SH_CONST[k]);
    for (const k of Object.keys(SH_ALIAS)) set(k, g(SH_ALIAS[k]));
  };

  function __makeComputed(map, names) {
    // Объект называет себя как в браузере: `[object CSSStyleDeclaration]`.
    const proto = (globalThis.CSSStyleDeclaration && CSSStyleDeclaration.prototype) || Object.prototype;
    // Заглушка интерфейса могла приехать без своего имени — тогда ставим его.
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'CSSStyleDeclaration', configurable: true });
      }
    } catch (e) {}
    // Форма как у браузера: собственные свойства объявления — это индексы и
    // имена в camelCase, и больше ничего; методы и `length` — на прототипе.
    // Дефисные имена читаются, но собственными свойствами не числятся, поэтому
    // за них отвечает Proxy.
    const decl = Object.create(__inlineStyleProto());
    __cssReaders.set(decl, { computed: true, names, map });
    const own = (name, d) => { try { Object.defineProperty(decl, name, d); } catch (e) {} };
    for (let i = 0; i < names.length; i++) own(String(i), { value: names[i], enumerable: true, configurable: true });
    for (const name of CSS_PROPS) {
      // `webkitBorderAfter` — это `-webkit-border-after`: у вендорных имён
      // дефис ведущий. А `webkitAlignItems` своего свойства не имеет вовсе —
      // это просто другое имя для `align-items`, и браузер отвечает по нему
      // тем же значением.
      const plain = name.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase()).toLowerCase();
      const keys = /^(webkit|moz|ms|o)-/.test(plain)
        ? ['-' + plain, plain, plain.replace(/^(webkit|moz|ms|o)-/, '')]
        : [plain];
      // Значением, а не акцессором: у браузера в описании свойства лежит
      // `value`, и `get` там нет вовсе. Вычисленный стиль всё равно снят на
      // один миг — меняться его значениям уже не от чего.
      let v = '';
      for (const k of keys) { const got = map.get(k); if (got) { v = got; break; } }
      own(name, { value: v, writable: true, enumerable: true, configurable: true });
    }
    const dashOf = (p) => String(p).replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
    return __ptProxy(decl, {
      // Только список имён: описания у свойств уже такие, как надо, а лишняя
      // ловушка стоила бы полторы миллисекунды на каждый перебор стиля.
      ownKeys: (t) => __withEpub(Reflect.ownKeys(t)),
      get: (t, p) => {
        if (typeof p === 'string' && EPUB_SET.has(p)) return undefined;
        if (typeof p === 'string' && !(p in t)) return map.get(p.toLowerCase()) || '';
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
  }

  /// Кегль, действующий на элементе: он наследуется, а `em` считается от него.
  function __usedFontSize(el) {
    if (el && el.nodeType === ELEMENT_NODE) {
      const hit = __passFont.get(el);
      if (hit !== undefined) return hit;
      const v = __usedFontSizeRaw(el);
      __passFont.set(el, v);
      return v;
    }
    return __usedFontSizeRaw(el);
  }

  const FONT_KEYWORDS = {
    'xx-small': 9, 'x-small': 10, small: 13, medium: 16, large: 18,
    'x-large': 24, 'xx-large': 32, 'xxx-large': 48,
  };

  function __usedFontSizeRaw(el) {
    let size = 16;
    const chain = [];
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) chain.push(e);
    // Поля формы не наследуют кегль страницы: движок браузера даёт им свой.
    const own = (el && el.localName) || '';
    if (own === 'input' || own === 'button' || own === 'select' || own === 'textarea') {
      size = UA_FORM_FONT;
      const raw = __cascadeFor(el).get('font-size');
      if (raw == null) return size;
    }
    // Моноширинное набирается своим кеглем: у браузера это тринадцать
    // пикселей, а не шестнадцать, и `pre` без своего правила отступает на
    // тринадцать, а не на шестнадцать.
    if (own !== 'textarea' && UA_MONO.has(own)) {
      size = 13;
      const raw = __cascadeFor(el).get('font-size');
      if (raw == null) return size;
    }
    for (let i = chain.length - 1; i >= 0; i--) {
      const raw = __cascadeFor(chain[i]).get('font-size');
      if (raw == null) {
        const f = UA_FONT_SIZE[(chain[i].localName || '').toLowerCase()];
        if (f) size *= f;
        continue;
      }
      let v = String(raw).trim().toLowerCase();
      // `rem` у самого корня значит начальный кегль, а не свой же.
      const e = chain[i];
      if (e.ownerDocument && e === e.ownerDocument.documentElement) v = v.replace(/(\d)rem\b/g, '$1em');
      if (FONT_KEYWORDS[v]) { size = FONT_KEYWORDS[v]; continue; }
      if (v === 'smaller') { size /= 1.2; continue; }
      if (v === 'larger') { size *= 1.2; continue; }
      // `em` и проценты — от кегля родителя, `calc()` и `clamp()` тоже.
      const px = __lengthPx(v, size, size);
      if (px != null && px >= 0) size = px;
    }
    return Math.round(size * 1e4) / 1e4;
  }

  /// Длина в пикселях, как её отдаёт браузер: `em` от кегля, проценты — от
  /// ширины родителя, всё прочее как есть.
  const __LENGTH_PROPS = /^(width|height|min-|max-|margin|padding|border-.*-width|top|right|bottom|left|inset|gap|font-size|line-height|text-indent|letter-spacing|word-spacing|outline-width|border-spacing|column-gap|row-gap)/;
  function __resolveLength(raw, prop, fontSize, el) {
    let v = String(raw);
    if (!__LENGTH_PROPS.test(prop)) return v;
    // Выражения браузер печатает готовым числом, если всё в них известно.
    if (__CALC_FN.test(v)) v = __ptCalcOut(v, fontSize, el);
    if (!/[\d.](?:em|rem|pt|%|[dsl]?v(?:h|w|min|max))/.test(v)) return v;
    return v.replace(/(-?[\d.]+)(em|rem|pt|[dsl]?vmin|[dsl]?vmax|[dsl]?vh|[dsl]?vw|%)(?![\w-])/g, (m, n, unit) => {
      const x = parseFloat(n);
      if (unit === 'pt') return (x * 4 / 3) + 'px';
      if (unit === 'em') return (x * fontSize) + 'px';
      if (unit === 'rem') return (x * __rootFontSize()) + 'px';
      if (unit.length > 2 && /^[dsl]v/.test(unit)) unit = unit.slice(1);
      // Доли окна браузер тоже печатает пикселями: `margin: 15vh auto` в
      // вычисленном стиле выходит числом, а не записью автора.
      if (unit === 'vh' || unit === 'vw' || unit === 'vmin' || unit === 'vmax') {
        const base = unit === 'vh' ? LAYOUT.H : unit === 'vw' ? LAYOUT.W
          : unit === 'vmin' ? Math.min(LAYOUT.W, LAYOUT.H) : Math.max(LAYOUT.W, LAYOUT.H);
        return (Math.round(x / 100 * base * 64) / 64) + 'px';
      }
      // Проценты по вертикали считаются тоже от ширины — так в спецификации.
      const base = __containingWidth(el);
      return base != null ? (Math.round(x / 100 * base * 64) / 64) + 'px' : m;
    });
  }

  /// Каждое `calc()`/`min()`/`max()`/`clamp()` верхнего уровня — в пиксели,
  /// если хватает данных; иначе остаётся как написано.
  function __ptCalcOut(v, fontSize, el) {
    let out = '', i = 0;
    const re = /(?:-webkit-)?(?:calc|min|max|clamp)\(/gi;
    for (;;) {
      re.lastIndex = i;
      const m = re.exec(v);
      if (!m) { out += v.slice(i); break; }
      if (m.index > 0 && /[\w-]/.test(v[m.index - 1])) { out += v.slice(i, re.lastIndex); i = re.lastIndex; continue; }
      let depth = 1, j = re.lastIndex;
      for (; j < v.length && depth; j++) {
        if (v[j] === '(') depth++;
        else if (v[j] === ')') depth--;
      }
      const part = v.slice(m.index, j);
      const needsBase = part.indexOf('%') >= 0;
      const px = __ptCalcPx(part, fontSize, needsBase ? __containingWidth(el) : null);
      out += v.slice(i, m.index) + (px == null ? part : (Math.round(px * 64) / 64) + 'px');
      i = j;
    }
    return out;
  }

  /// Ширина содержимого блока, в котором лежит элемент.
  function __containingWidth(el) {
    const parent = el && el.parentNode;
    if (!parent || parent.nodeType !== ELEMENT_NODE) return LAYOUT.W;
    const b = parent.__ptBoxV === __layoutBuilt ? parent.__ptBox : null;
    return b ? b.cw : LAYOUT.W;
  }

  function __boxOf(el) {
    if (!el || el.nodeType !== ELEMENT_NODE) return null;
    const doc = el.ownerDocument;
    if (doc && doc !== globalThis.document) {
      // Узел чужого документа: раскладывает его тот реалм, которому он
      // принадлежит, и отметку надо спрашивать у документа, а не у себя.
      try {
        const win = doc.defaultView;
        if (win && typeof win.__pt_relayout === 'function') win.__pt_relayout();
      } catch (e) {}
      return doc.__ptLayoutV != null && el.__ptBoxV === doc.__ptLayoutV ? el.__ptBox : null;
    }
    __relayout();
    return el.__ptBoxV === __layoutBuilt ? el.__ptBox : null; // detached/hidden → no box
  }

  /// Список прямоугольников: у браузера это `DOMRectList`, а не массив, и имя
  /// объекта читают.
  function __ptRectList(items) {
    const list = items.slice();
    list.item = function item(i) { return this[i] || null; };
    try { Object.defineProperty(list, Symbol.toStringTag, { value: 'DOMRectList', configurable: true }); } catch (e) {}
    return list;
  }

  // Прямоугольник и метрики текста — не литералы, а объекты с именем. Страница
  // спрашивает `Object.prototype.toString.call(el.getBoundingClientRect())` и
  // должна услышать `[object DOMRect]`, а не `[object Object]`; у нас это были
  // безымянные объекты, и `measureText` тоже. Состав прототипов снят с Chrome
  // 151 перечислением: у `DOMRectReadOnly` десять имён, у `DOMRect` пять своих
  // поверх них, у `TextMetrics` одиннадцать.
  const __rectVals = new WeakMap();
  class DOMRectReadOnly {
    constructor(x, y, w, h) {
      __rectVals.set(this, { x: +x || 0, y: +y || 0, w: +w || 0, h: +h || 0 });
    }
    get x() { return __rectVals.get(this).x; }
    get y() { return __rectVals.get(this).y; }
    get width() { return __rectVals.get(this).w; }
    get height() { return __rectVals.get(this).h; }
    get top() { const v = __rectVals.get(this); return Math.min(v.y, v.y + v.h); }
    get right() { const v = __rectVals.get(this); return Math.max(v.x, v.x + v.w); }
    get bottom() { const v = __rectVals.get(this); return Math.max(v.y, v.y + v.h); }
    get left() { const v = __rectVals.get(this); return Math.min(v.x, v.x + v.w); }
    toJSON() {
      return { x: this.x, y: this.y, width: this.width, height: this.height,
               top: this.top, right: this.right, bottom: this.bottom, left: this.left };
    }
  }
  class DOMRect extends DOMRectReadOnly {
    get x() { return __rectVals.get(this).x; }
    set x(v) { __rectVals.get(this).x = +v || 0; }
    get y() { return __rectVals.get(this).y; }
    set y(v) { __rectVals.get(this).y = +v || 0; }
    get width() { return __rectVals.get(this).w; }
    set width(v) { __rectVals.get(this).w = +v || 0; }
    get height() { return __rectVals.get(this).h; }
    set height(v) { __rectVals.get(this).h = +v || 0; }
  }
  for (const [C, n] of [[DOMRectReadOnly, 'DOMRectReadOnly'], [DOMRect, 'DOMRect']]) {
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: n, configurable: true }); } catch (e) {}
    globalThis[n] = globalThis.__pt_native ? __pt_native(C) : C;
  }
  globalThis.__pt_makeRect = (x, y, w, h) => new DOMRect(x, y, w, h);

  // Точка: у Chrome DOMPointReadOnly (x, y, z, w, matrixTransform, toJSON,
  // fromPoint) и DOMPoint поверх неё с сеттерами. Была заглушкой без значений.
  const __ptVals = new WeakMap();
  const __ptNum = (v) => { const n = +v; return Number.isNaN(n) ? NaN : n; };
  class DOMPointReadOnly {
    constructor(x = 0, y = 0, z = 0, w = 1) {
      __ptVals.set(this, { x: __ptNum(x), y: __ptNum(y), z: __ptNum(z), w: __ptNum(w) });
    }
    get x() { return __ptVals.get(this).x; }
    get y() { return __ptVals.get(this).y; }
    get z() { return __ptVals.get(this).z; }
    get w() { return __ptVals.get(this).w; }
    matrixTransform(m) {
      const v = __ptVals.get(this);
      const M = (m && typeof m === 'object') ? m : {};
      const g = (k, d) => (M[k] === undefined ? d : +M[k]);
      const m11 = g('m11', g('a', 1)), m12 = g('m12', g('b', 0)), m13 = g('m13', 0), m14 = g('m14', 0);
      const m21 = g('m21', g('c', 0)), m22 = g('m22', g('d', 1)), m23 = g('m23', 0), m24 = g('m24', 0);
      const m31 = g('m31', 0), m32 = g('m32', 0), m33 = g('m33', 1), m34 = g('m34', 0);
      const m41 = g('m41', g('e', 0)), m42 = g('m42', g('f', 0)), m43 = g('m43', 0), m44 = g('m44', 1);
      return new DOMPoint(m11 * v.x + m21 * v.y + m31 * v.z + m41 * v.w,
                          m12 * v.x + m22 * v.y + m32 * v.z + m42 * v.w,
                          m13 * v.x + m23 * v.y + m33 * v.z + m43 * v.w,
                          m14 * v.x + m24 * v.y + m34 * v.z + m44 * v.w);
    }
    toJSON() { const v = __ptVals.get(this); return { x: v.x, y: v.y, z: v.z, w: v.w }; }
    static fromPoint(o) { const M = (o && typeof o === 'object') ? o : {}; return new this(M.x === undefined ? 0 : M.x, M.y === undefined ? 0 : M.y, M.z === undefined ? 0 : M.z, M.w === undefined ? 1 : M.w); }
  }
  class DOMPoint extends DOMPointReadOnly {
    get x() { return __ptVals.get(this).x; }
    set x(v) { __ptVals.get(this).x = __ptNum(v); }
    get y() { return __ptVals.get(this).y; }
    set y(v) { __ptVals.get(this).y = __ptNum(v); }
    get z() { return __ptVals.get(this).z; }
    set z(v) { __ptVals.get(this).z = __ptNum(v); }
    get w() { return __ptVals.get(this).w; }
    set w(v) { __ptVals.get(this).w = __ptNum(v); }
    static fromPoint(o) { return DOMPointReadOnly.fromPoint.call(DOMPoint, o); }
  }
  for (const [C, n] of [[DOMPointReadOnly, 'DOMPointReadOnly'], [DOMPoint, 'DOMPoint']]) {
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: n, configurable: true }); } catch (e) {}
    globalThis[n] = globalThis.__pt_native ? __pt_native(C) : C;
  }

  // `TextMetrics`: значения на прототипе, у самого объекта своих свойств нет —
  // как и у всего, что отдаёт браузер. Базовые линии считаются от метрик
  // гарнитуры: висячая — четыре пятых подъёма, иероглифическая — минус спуск.
  const __tmVals = new WeakMap();
  const TM_KEYS = ['width', 'actualBoundingBoxLeft', 'actualBoundingBoxRight',
                   'actualBoundingBoxAscent', 'actualBoundingBoxDescent',
                   'fontBoundingBoxAscent', 'fontBoundingBoxDescent',
                   'alphabeticBaseline', 'hangingBaseline', 'ideographicBaseline'];
  class TextMetrics {}
  for (const k of TM_KEYS) {
    Object.defineProperty(TextMetrics.prototype, k, {
      get() { return (__tmVals.get(this) || {})[k] || 0; },
      enumerable: false, configurable: true,
    });
  }
  try { Object.defineProperty(TextMetrics.prototype, Symbol.toStringTag, { value: 'TextMetrics', configurable: true }); } catch (e) {}
  globalThis.TextMetrics = globalThis.__pt_native ? __pt_native(TextMetrics) : TextMetrics;
  globalThis.__pt_makeMetrics = (v) => {
    const m = Object.create(TextMetrics.prototype);
    __tmVals.set(m, {
      width: v.width || 0,
      actualBoundingBoxLeft: v.left || 0, actualBoundingBoxRight: v.right || 0,
      actualBoundingBoxAscent: v.ascent || 0, actualBoundingBoxDescent: v.descent || 0,
      fontBoundingBoxAscent: v.fontAscent || 0, fontBoundingBoxDescent: v.fontDescent || 0,
      alphabeticBaseline: 0,
      // Chrome держит висячую базовую линию во float32 (10.399999618530273).
      hangingBaseline: Math.fround((v.fontAscent || 0) * 0.8),
      ideographicBaseline: -(v.fontDescent || 0),
    });
    return m;
  };

  // Градиент, узор и выделение — тоже объекты с именем, а не литералы. У
  // градиента вдобавок наружу светила наша метка `__ptGrad`: собственное
  // свойство, которого у браузерного объекта нет ни одного.
  const __gradVals = new WeakMap();
  class CanvasGradient {
    addColorStop(pos, color) {
      const g = __gradVals.get(this);
      if (g) g.add(pos, color);
    }
  }
  const __patVals = new WeakMap();
  class CanvasPattern {
    setTransform(m) { const p = __patVals.get(this); if (p) p.transform = m || null; }
  }
  class Selection {
    getRangeAt() { throw new (globalThis.DOMException || Error)("Failed to execute 'getRangeAt' on 'Selection': 0 is not a valid index.", 'IndexSizeError'); }
    removeAllRanges() {} addRange() {} removeRange() {} empty() {} collapse() {}
    collapseToStart() {} collapseToEnd() {} extend() {} modify() {}
    selectAllChildren() {} setBaseAndExtent() {} setPosition() {}
    deleteFromDocument() {} containsNode() { return false; }
    getComposedRanges() { return []; }
    toString() { return ''; }
  }
  for (const [k, v] of Object.entries({
    anchorNode: null, anchorOffset: 0, focusNode: null, focusOffset: 0,
    baseNode: null, baseOffset: 0, extentNode: null, extentOffset: 0,
    isCollapsed: true, rangeCount: 0, type: 'None', direction: 'none',
  })) Object.defineProperty(Selection.prototype, k, { get: () => v, configurable: true });
  for (const [C, n] of [[CanvasGradient, 'CanvasGradient'], [CanvasPattern, 'CanvasPattern'],
                        [Selection, 'Selection']]) {
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: n, configurable: true }); } catch (e) {}
    globalThis[n] = globalThis.__pt_native ? __pt_native(C) : C;
  }
  globalThis.__pt_makeGradient = (state) => {
    const g = Object.create(CanvasGradient.prototype);
    __gradVals.set(g, state);
    return g;
  };
  globalThis.__pt_makePattern = (state) => {
    const p = Object.create(CanvasPattern.prototype);
    __patVals.set(p, state || {});
    return p;
  };
  {
    const sel = Object.create(Selection.prototype);
    globalThis.getSelection = globalThis.__pt_native
      ? __pt_native(function getSelection() { return sel; })
      : function getSelection() { return sel; };
    // На прототипе, а не на самом документе: у документа собственное свойство
    // ровно одно — `location`, и лишнее там видно первой же проверкой.
    const D = globalThis.document && Object.getPrototypeOf(globalThis.document);
    if (D) {
      try {
        const docSel = globalThis.__pt_native ? __pt_native(function getSelection() { return this === globalThis.document ? sel : null; }) : function getSelection() { return this === globalThis.document ? sel : null; };
        Object.defineProperty(D, 'getSelection', {
          value: docSel, writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
  }

  function __rectFromBox(b) {
    return b ? new DOMRect(b.x, b.y, b.w, b.h) : new DOMRect(0, 0, 0, 0);
  }

  function __elementFromPoint(x, y) {
    __relayout();
    if (x == null || y == null || x < 0 || y < 0) return null;
    // Самый глубокий и самый поздний из тех, чья коробка накрывает точку.
    for (let i = __boxes.length - 1; i >= 0; i--) {
      const el = __boxes[i], b = el.__ptBox;
      if (!b || b.w <= 0 || b.h <= 0) continue;
      if (x >= b.x && x < b.x + b.w && y >= b.y && y < b.y + b.h) return el;
    }
    return null;
  }

  function __focusableAncestor(el) {
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
      const t = e.tagName;
      if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || t === 'BUTTON') return e;
      if (t === 'A' && __ptHasA(e, 'href')) return e;
      if (__ptHasA(e, 'tabindex')) return e;
      if (e.isContentEditable) return e;
    }
    return null;
  }

  const __quad = (b) => [b.x, b.y, b.x + b.w, b.y, b.x + b.w, b.y + b.h, b.x, b.y + b.h];

  // Visible text of an element: skip hidden subtrees, gather text nodes, collapse
  // runs of whitespace. Not a full innerText (no per-block newlines) but enough
  // for reading rendered text.
  const __INNERTEXT_SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD', 'TITLE']);
  function __innerText(el) {
    if (!el || el.nodeType !== ELEMENT_NODE) return '';
    // Неотрисованный элемент отвечает своим `textContent` — со стилями,
    // скриптами и всем, что внутри. Мы отвечали пустотой, а это разные вещи:
    // у Chrome `d.style.display='none'; d.innerText` даёт «.z{color:red}текст».
    if (__isHiddenEl(el)) return el.textContent || '';
    // `innerText` renders only visible content — the text inside <script>/<style>
    // etc. is not rendered, so it must not leak into it (`textContent` includes it).
    if (__INNERTEXT_SKIP.has(el.tagName)) return '';
    let s = '';
    for (const c of el.__ptKids) {
      if (c.nodeType === TEXT_NODE) s += c.data;
      else if (c.nodeType === ELEMENT_NODE && !__isHiddenEl(c)) s += ' ' + __innerText(c);
    }
    return s.replace(/\s+/g, ' ').trim();
  }

  // Called from the CDP layer (server.rs). Nodes are resolved there and passed in.
  globalThis.__pt_layoutMetrics = () => ({ w: LAYOUT.W, h: LAYOUT.H });
  globalThis.__pt_boxModel = (n) => {
    const b = __boxOf(n); if (!b) return null;
    const q = __quad(b);
    return { content: q, padding: q, border: q, margin: q, width: b.w, height: b.h };
  };
  globalThis.__pt_contentQuads = (n) => { const b = __boxOf(n); return b ? [__quad(b)] : []; };
  globalThis.__pt_focusNode = (n) => { if (n && n.focus) { n.focus(); return true; } return false; };

  // A mouse action at (x,y): resolve the topmost element there and fire the
  // matching pointer + mouse events, synthesizing `click` on release over the
  // same element that received the press (as a real browser does).
  // Точка попала во фрейм? Тогда клик принадлежит не нам: движок спустится в
  // его контекст и повторит попадание уже в координатах фрейма. Виджет
  // Turnstile живёт ровно так — iframe в закрытой тени хоста, — и без этого
  // спуска нажать его нечем.
  // Первый видимый управляющий элемент документа — чекбокс, переключатель или
  // кнопка, — вместе с точкой, куда по нему бьют. Ищет и в теневых деревьях:
  // виджеты держат свой UI именно там, и обычный querySelector их не находит.
  // Знания о конкретной капче здесь нет и быть не должно — есть «нажимаемое».
  // `widgetOnly` — искать только внутри теневых деревьев: собственная форма
  // страницы виджету не принадлежит, и нажимать её кнопку «отправить» нельзя ни
  // при каких обстоятельствах. Во фрейме виджета ограничение снимается: там всё
  // содержимое и есть виджет.
  globalThis.__pt_findControl = (widgetOnly) => {
    __relayout();
    const seen = [];
    const scan = (root, shadowed) => {
      for (const n of (root.__ptKids || [])) {
        if (n.nodeType !== ELEMENT_NODE) continue;
        if (!__isHiddenEl(n)) {
          const role = (n.getAttribute && __ptGetA(n, 'role')) || '';
          const type = (n.getAttribute && __ptGetA(n, 'type')) || '';
          const control = (n.tagName === 'INPUT' && /^(checkbox|radio|submit|button)$/i.test(type))
            || n.tagName === 'BUTTON'
            || role === 'checkbox' || role === 'button' || role === 'switch';
          if (control && (shadowed || !widgetOnly)) {
            // Настоящий флажок виджета спрятан: нулевого размера, с прозрачной
            // подложкой поверх. Человек нажимает не его, а то, что видит, —
            // ближайшую обёртку с настоящей коробкой. Пока раскладка была
            // выдуманной, невидимый вход отвечал размером во всё окно и промаха
            // не было; с настоящей раскладкой промах появился.
            let r = n.getBoundingClientRect();
            if (!(r.width > 0 && r.height > 0)) {
              for (let a = n.parentNode; a && a.nodeType === ELEMENT_NODE; a = a.parentNode) {
                const ar = a.getBoundingClientRect();
                if (ar.width > 0 && ar.height > 0 && ar.width <= 400 && ar.height <= 200) { r = ar; break; }
              }
            }
            if (r.width > 0 && r.height > 0) {
              seen.push({ tag: n.tagName, type: type || role,
                          x: r.x + Math.min(r.width, 24) / 2,
                          y: r.y + Math.min(r.height, 24) / 2,
                          at: Math.round(r.y),
                          label: (n.getAttribute && __ptGetA(n, 'aria-label')) || '' });
            }
          }
          if (n.__ptShadow) scan(n.__ptShadow, true);
          scan(n, shadowed);
        }
      }
    };
    const de = globalThis.document && globalThis.document.documentElement;
    if (de) scan(de, false);
    return __ptJSON.stringify(seen.slice(0, 8));
  };

  // Отладка решателя: все поля ввода и подписи документа (с тенями) с их
  // прямоугольниками и видимостью — чтобы понять, почему нечего нажать.
  globalThis.__pt_ctlDebug = () => {
    const out = [];
    const walk = (n, depth) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.nodeType !== ELEMENT_NODE) continue;
        const t = c.tagName;
        if (t === 'INPUT' || t === 'LABEL' || t === 'BUTTON' || (c.getAttribute && __ptGetA(c, 'role'))) {
          let r = null; try { r = c.getBoundingClientRect(); } catch (e) {}
          let cs = null; try { cs = getComputedStyle(c); } catch (e) {}
          out.push([t, (c.getAttribute && (__ptGetA(c, 'type') || __ptGetA(c, 'role'))) || '', depth,
            r ? [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)] : null,
            cs ? cs.display + '/' + cs.visibility + '/' + cs.opacity : '', c.isConnected]);
        }
        if (c.__ptShadow) walk(c.__ptShadow, depth + 1);
        walk(c, depth);
      }
    };
    if (globalThis.document) walk(globalThis.document, 0);
    return __ptJSON.stringify({ ctl: out.slice(0, 20), body: globalThis.document && document.body ? (document.body.innerText || '').slice(0, 120) : '' });
  };

  // Прямоугольник элемента кадра по его номеру — где бы он ни стоял, в том
  // числе в теневом дереве (кадр виджета живёт в закрытой тени).
  globalThis.__pt_frameRectById = (id) => {
    const walk = (n) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.nodeType !== ELEMENT_NODE) continue;
        if (c.__ptLocal === 'iframe' && c.__ptFrameId === id) return c;
        const inShadow = c.__ptShadow ? walk(c.__ptShadow) : null;
        if (inShadow) return inShadow;
        const deeper = walk(c);
        if (deeper) return deeper;
      }
      return null;
    };
    const el = globalThis.document && walk(globalThis.document);
    if (!el) return '';
    const r = el.getBoundingClientRect();
    return __ptJSON.stringify({ x: r.x, y: r.y, w: r.width, h: r.height });
  };

  globalThis.__pt_hitFrame = (x, y) => {
    for (let el = __elementFromPoint(x, y); el && el.nodeType === ELEMENT_NODE; el = el.parentNode) {
      if (el.__ptLocal === 'iframe' && el.__ptFrameId) {
        const r = el.getBoundingClientRect();
        // Один к одному, как в настоящем окне: фрейм не сжимает содержимое под
        // свою рамку, он показывает его верх, а остальное уходит под обрез.
        // Точка внутри рамки — та же точка в координатах фрейма.
        return __ptJSON.stringify({ frame: el.__ptFrameId, x: x - r.x, y: y - r.y });
      }
    }
    return '';
  };


  /// Поле, которое активирует подпись под указателем: либо названное в `for`,
  /// либо первое поле внутри самой подписи. Ничего не нашлось — null.
  function __labelFor(el) {
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
      if (e.tagName !== 'LABEL') continue;
      const id = e.getAttribute && __ptGetA(e, 'for');
      if (id) {
        const root = e.getRootNode ? e.getRootNode() : (globalThis.document || null);
        const found = root && root.getElementById ? root.getElementById(id)
                    : (globalThis.document && globalThis.document.getElementById(id));
        if (found) return found;
      }
      const inner = e.querySelector && e.querySelector('input, select, textarea, button');
      if (inner) return inner;
    }
    return null;
  }

  // Ввод мыши движком — так, как его видит страница в Chrome (сверено по
  // записи настоящего нажатия в кадре виджета): у указательных событий
  // дробные координаты, у мышиных — целые; экранные — с положением окна и
  // кадра; сдвиг от прошлой точки; у движения button −1 (у мышиного 0) и
  // which 0; у нажатия which 1; click — PointerEvent; у мышиных событий
  // sourceCapabilities, у указательных — null. `ox`/`oy` — экранная точка
  // начала кадра (передаёт ядро; без них — начало своего окна).
  let __lastSX = null, __lastSY = null, __idc = null, __winFocused = false;
  const __devCaps = () => {
    if (__idc) return __idc;
    try { __idc = new InputDeviceCapabilities({ firesTouchEvents: false }); if (globalThis.__pt_idcSet) __pt_idcSet(__idc, false); } catch (e) { __idc = null; }
    return __idc;
  };
  const __q = (v) => Math.round(v * 256) / 256;
  globalThis.__pt_screenOrigin = () => {
    const w = globalThis;
    const ox = (w.screenX || 0) + Math.max(0, ((w.outerWidth || 0) - (w.innerWidth || 0)) / 2);
    const oy = (w.screenY || 0) + Math.max(0, (w.outerHeight || 0) - (w.innerHeight || 0));
    return __ptJSON.stringify([ox, oy]);
  };
  globalThis.__pt_mouse = (type, x, y, button, clickCount, ox, oy) => {
    x = __q(+x || 0); y = __q(+y || 0);
    const el = __elementFromPoint(x, y) || (globalThis.document && globalThis.document.body);
    if (!el) return false;
    if (ox === undefined || oy === undefined) {
      try { const o = __ptJSON.parse(globalThis.__pt_screenOrigin()); ox = o[0]; oy = o[1]; } catch (e) { ox = 0; oy = 0; }
    }
    const sx = __q(x + ox), sy = __q(y + oy);
    const mx = __lastSX === null ? 0 : Math.round(sx - __lastSX), my = __lastSY === null ? 0 : Math.round(sy - __lastSY);
    let r = null; try { r = el.getBoundingClientRect(); } catch (e) {}
    const rl = r ? r.left : 0, rt = r ? r.top : 0;
    const scX = globalThis.scrollX || 0, scY = globalThis.scrollY || 0;
    const b = button === 'right' ? 2 : button === 'middle' ? 1 : (button | 0);
    const down = type === 'mousePressed', up = type === 'mouseReleased', move = type === 'mouseMoved';
    const clicks = clickCount || 1;
    // Поля, которых нет в словаре конструктора, ставятся после создания.
    const finish = (ev, mouse, extra) => {
      const cx = mouse ? Math.trunc(x) : x, cy = mouse ? Math.trunc(y) : y;
      const E = ev.__ptE;
      if (E) Object.assign(E, {
        clientX: cx, clientY: cy, x: cx, y: cy,
        screenX: mouse ? Math.trunc(sx) : sx, screenY: mouse ? Math.trunc(sy) : sy,
        pageX: mouse ? Math.trunc(x + scX) : x + scX, pageY: mouse ? Math.trunc(y + scY) : y + scY,
        offsetX: mouse ? Math.round(x - rl) : x - rl, offsetY: mouse ? Math.round(y - rt) : y - rt,
        layerX: Math.trunc(x + scX), layerY: Math.trunc(y + scY),
        movementX: move ? mx : 0, movementY: move ? my : 0,
        sourceCapabilities: mouse ? __devCaps() : null,
      }, extra || {});
      return __ptTrust(ev);
    };
    const base = { bubbles: true, cancelable: true, composed: true, view: globalThis, clientX: x, clientY: y, screenX: sx, screenY: sy };
    const ptrInit = (extra) => Object.assign({}, base, { pointerId: 1, pointerType: 'mouse', isPrimary: true, width: 1, height: 1 }, extra || {});
    const P = (t, extra, fields) => { const ev = new PointerEvent(t, ptrInit(extra)); finish(ev, false, fields); return ev; };
    const M = (t, init, fields) => { const ev = new MouseEvent(t, Object.assign({}, base, init)); finish(ev, true, fields); return ev; };
    const send = (target, ev) => target.dispatchEvent(ev);
    const hoverTo = (next) => {
      const prev = __hoverEl;
      if (prev === next) return;
      const nb = () => { const o = { ...base }; o.bubbles = false; o.cancelable = false; return o; };
      if (prev && prev.isConnected !== false) {
        send(prev, P('pointerout', { button: -1, relatedTarget: next }, { button: -1, which: 0, detail: 0 }));
        send(prev, P('pointerleave', { button: -1, bubbles: false, cancelable: false, relatedTarget: next }, { button: -1, which: 0, detail: 0 }));
        send(prev, M('mouseout', { relatedTarget: next }, { which: 0, detail: 0 }));
        send(prev, M('mouseleave', { ...nb(), relatedTarget: next }, { which: 0, detail: 0 }));
      }
      __hoverEl = next;
      send(next, P('pointerover', { button: -1, relatedTarget: prev || null }, { button: -1, which: 0, detail: 0 }));
      send(next, P('pointerenter', { button: -1, bubbles: false, cancelable: false, relatedTarget: prev || null }, { button: -1, which: 0, detail: 0 }));
      send(next, M('mouseover', { relatedTarget: prev || null }, { which: 0, detail: 0 }));
      send(next, M('mouseenter', { ...nb(), relatedTarget: prev || null }, { which: 0, detail: 0 }));
    };
    const held = __mouseDownEl ? 1 : 0;
    if (down) {
      hoverTo(el);
      send(el, P('pointerdown', { button: b, buttons: 1, pressure: 0.5 }, { which: b + 1, detail: 0 }));
      send(el, M('mousedown', { button: b, buttons: 1, detail: clicks }, { which: b + 1 }));
      // Окно, получившее нажатие впервые, само получает focus — до элемента.
      if (!__winFocused) {
        __winFocused = true;
        try { const wf = new FocusEvent('focus', { bubbles: false, cancelable: false, composed: false }); globalThis.dispatchEvent(__ptTrust(wf)); } catch (e) {}
      }
      const f = __focusableAncestor(el);
      try { Object.defineProperty(globalThis, '__ptFocusCaps', { value: __devCaps(), writable: true, configurable: true }); } catch (e) {}
      try {
        if (f) f.focus(); else if (globalThis.document) { const a = globalThis.document.activeElement; if (a && a.blur) a.blur(); }
      } finally { try { globalThis.__ptFocusCaps = null; } catch (e) {} }
      __mouseDownEl = el;
    } else if (up) {
      send(el, P('pointerup', { button: b, buttons: 0, pressure: 0 }, { which: b + 1, detail: 0 }));
      send(el, M('mouseup', { button: b, buttons: 0, detail: clicks }, { which: b + 1 }));
      if (__mouseDownEl === el) {
        const isBox = (n) => n && n.tagName === 'INPUT' && /^(checkbox|radio)$/i.test(__ptGetA(n, 'type') || '');
        // Флажок переключается до click (его обработчик читает новое
        // состояние), а input/change идут после click — как у браузера; click
        // с preventDefault откатывает переключение.
        const clickOn = (target) => {
          const box = isBox(target) ? target : null;
          const was = box ? box.checked : null;
          if (box) box.checked = String(__ptGetA(box, 'type')).toLowerCase() === 'radio' ? true : !box.checked;
          // click у Chrome — PointerEvent, но с целыми координатами мыши и
          // isPrimary false.
          const ev = new PointerEvent('click', ptrInit({ button: b, buttons: 0, pressure: 0, detail: clicks, isPrimary: false }));
          finish(ev, true, { which: b + 1, detail: clicks, isPrimary: false });
          const ok = send(target, ev);
          if (box) {
            if (!ok) box.checked = was;
            else if (box.checked !== was) {
              box.dispatchEvent(__ptTrust(new Event('input', { bubbles: true, composed: true })));
              box.dispatchEvent(__ptTrust(new Event('change', { bubbles: true })));
            }
          }
        };
        clickOn(el);
        // Нажатие на подпись — это нажатие на её поле. Виджет прячет свой
        // флажок нулевым размером и кладёт поверх видимую обёртку внутри
        // `<label>`; человек попадает в обёртку, а переключается флажок.
        const lbl = __labelFor(el);
        if (lbl && lbl !== el) {
          clickOn(lbl);
          if (lbl.focus) lbl.focus();
        }
      }
      __mouseDownEl = null;
    } else if (move) {
      hoverTo(el);
      send(el, P('pointermove', { button: -1, buttons: held, pressure: held ? 0.5 : 0 }, { button: -1, which: 0, detail: 0 }));
      send(el, M('mousemove', { button: 0, buttons: held }, { which: 0, detail: 0 }));
    }
    __lastSX = sx; __lastSY = sy;
    return true;
  };

  const __editable = (el) => el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
  function __insertInto(el, text) {
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      el.value = (el.value || '') + text;
    } else if (el.isContentEditable) {
      el.textContent = (el.textContent || '') + text;
    } else return false;
    el.dispatchEvent(__ptTrust(new InputEvent('input', { bubbles: true, data: text, inputType: 'insertText' })));
    return true;
  }
  globalThis.__pt_insertText = (text) => {
    const el = globalThis.document && globalThis.document.activeElement;
    return __editable(el) ? __insertInto(el, String(text)) : false;
  };

  // A key action on the focused element. Fires keydown/keyup (+ keypress for a
  // printable key), and mirrors real editing side effects: printable `text`
  // is inserted, Backspace deletes the last char, both raising `input`.
  globalThis.__pt_key = (type, init) => {
    init = init || {};
    const doc = globalThis.document;
    const el = (doc && doc.activeElement) || (doc && doc.body);
    if (!el) return false;
    const name = { keyDown: 'keydown', rawKeyDown: 'keydown', keyUp: 'keyup', char: 'keypress' }[type] || type;
    const ev = { bubbles: true, cancelable: true, key: init.key || '', code: init.code || '', keyCode: init.keyCode || 0 };
    el.dispatchEvent(__ptTrust(new KeyboardEvent(name, ev)));
    if (name === 'keydown') {
      if (init.text) { if (__editable(el)) __insertInto(el, init.text); }
      else if (init.key === 'Backspace' && __editable(el)) {
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.value = String(el.value || '').slice(0, -1);
        else el.textContent = String(el.textContent || '').slice(0, -1);
        el.dispatchEvent(__ptTrust(new InputEvent('input', { bubbles: true, inputType: 'deleteContentBackward' })));
      }
    }
    return true;
  };

  globalThis.__pt_getProps = (id) => {
    const o = __ptObjs.get(id); const out = [];
    if (o != null) {
      for (const k of Object.getOwnPropertyNames(o)) {
        // Report the REAL descriptor flags. Reporting non-enumerable props (e.g.
        // an array's `length`) as enumerable makes Puppeteer's iterator drain
        // (which stops when getProperties returns 0 enumerable entries) loop
        // forever — the root cause of page.$/$$/$eval hanging.
        let d; try { d = Object.getOwnPropertyDescriptor(o, k); } catch (e) { continue; }
        if (!d) continue;
        let val; try { val = 'value' in d ? d.value : o[k]; } catch (e) { continue; }
        out.push({
          name: String(k), value: globalThis.__pt_wrap(val, false),
          configurable: !!d.configurable, enumerable: !!d.enumerable,
          writable: !!d.writable, isOwn: true,
        });
      }
    }
    return out;
  };
})();
