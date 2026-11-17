/* HisobGo: o'zbek tili — lotin va kirill yozuvlari.
   Interfeys matni lotinda yoziladi; "Кирилл" tanlanganda sahifadagi matnlar, placeholder va
   sarlavhalar avtomatik kirillchaga o'giriladi (yangi chizilgan elementlar ham).
   Kodlar (SKU, chek raqami), qisqartmalar va brend nomlari o'zgarmaydi. */
(function () {
  "use strict";
  var KEY = "hg_lang";
  var lang = "lat";
  try { lang = localStorage.getItem(KEY) === "cyr" ? "cyr" : "lat"; } catch (e) {}

  var KEEP = {};
  ("hisobgo telegram excel csv uzcard humo click payme vip gold silver pos crm sku otp totp stir tin api qr id uzs " +
    "pdf url usd gmt utc ok sms bot").split(" ").forEach(function (w) { KEEP[w] = 1; });

  var APOS = "['ʻʼ’‘`]";
  var MAP = { a: "а", b: "б", d: "д", f: "ф", g: "г", h: "ҳ", i: "и", j: "ж", k: "к", l: "л", m: "м", n: "н", o: "о", p: "п", q: "қ", r: "р", s: "с", t: "т", u: "у", v: "в", x: "х", y: "й", z: "з", e: "е" };
  var CAPS = function (s) { return s.toUpperCase(); };

  // bitta so'z (faqat harflar va ichki apostroflar)
  function word(w) {
    var allUpper = w.length > 1 && w === w.toUpperCase() && w !== w.toLowerCase();
    var s = w.toLowerCase().replace(new RegExp(APOS, "g"), "'");
    var out = "", i = 0, n = s.length;
    while (i < n) {
      var c = s[i], d = s.substr(i, 2);
      var atStart = i === 0;
      if (d === "yo" && s[i + 2] === "'") { out += "й"; i++; continue; }  // yo'q -> йўқ
      if (d === "o'") { out += "ў"; i += 2; continue; }
      if (d === "g'") { out += "ғ"; i += 2; continue; }
      if (d === "sh") { out += "ш"; i += 2; continue; }
      if (d === "ch") { out += "ч"; i += 2; continue; }
      if (d === "ng") { out += "нг"; i += 2; continue; }
      if (d === "yo") { out += "ё"; i += 2; continue; }
      if (d === "yu") { out += "ю"; i += 2; continue; }
      if (d === "ya") { out += "я"; i += 2; continue; }
      if (d === "ye") { out += "е"; i += 2; continue; }
      if (c === "e") { out += atStart ? "э" : "е"; i++; continue; }
      if (c === "c") { out += /[eiy]/.test(s[i + 1] || "") ? "с" : "к"; i++; continue; }  // chet tili so'zlari
      if (c === "w") { out += "в"; i++; continue; }
      if (c === "'") { out += i === 0 || i === n - 1 ? "" : "ъ"; i++; continue; }
      out += MAP[c] || c; i++;
    }
    // bosh harf / hammasi katta harf
    if (allUpper) return CAPS(out);
    if (w[0] !== w[0].toLowerCase()) return out.charAt(0).toUpperCase() + out.slice(1);
    return out;
  }

  var TOKEN = /[A-Za-z0-9ʻʼ’‘'`-]+/g;
  function toCyr(str) {
    if (!str || !/[A-Za-z]/.test(str)) return str;
    return str.split(/(\s+)/).map(function (chunk) {
      if (/@|_|:\/\/|\.[a-z]{2,}\b/i.test(chunk)) return chunk;  // email, havola, bot nomi
      return chunk.replace(TOKEN, function (tok) {
        if (/\d/.test(tok)) return tok;                          // kodlar: CHK-4F2A, P-1A2B
        return tok.split("-").map(function (part) {
          var m = /^(['ʻʼ’‘`]*)(.*?)(['ʻʼ’‘`]*)$/.exec(part);
          var core = m[2];
          if (!core || KEEP[core.toLowerCase()]) return part;
          return m[1] + word(core) + m[3];
        }).join("-");
      });
    }).join("");
  }

  var orig = new WeakMap();      // matn tuguni -> asl (lotin) matn
  var origAttr = new WeakMap();  // element -> { atribut: asl }
  var ATTRS = ["placeholder", "title", "aria-label", "alt"];
  var SKIP = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, CODE: 1, NOSCRIPT: 1 };
  var busy = false;

  function skipEl(el) {
    for (; el && el.nodeType === 1; el = el.parentNode) {
      if (SKIP[el.tagName] || (el.classList && (el.classList.contains("font-mono-code") || el.hasAttribute("data-nt")))) return true;
    }
    return false;
  }

  function doText(node) {
    if (!node.parentNode || skipEl(node.parentNode)) return;
    var cur = node.nodeValue, was = orig.has(node) ? orig.get(node) : null;
    if (was !== null && toCyr(was) === cur) return;  // allaqachon o'girilgan
    var next = toCyr(cur);
    if (next !== cur) { orig.set(node, cur); node.nodeValue = next; }
  }
  function doAttrs(el) {
    if (skipEl(el)) return;
    ATTRS.forEach(function (a) {
      if (!el.hasAttribute(a)) return;
      var cur = el.getAttribute(a), store = origAttr.get(el) || {};
      if (a in store && toCyr(store[a]) === cur) return;
      var next = toCyr(cur);
      if (next !== cur) { store[a] = cur; origAttr.set(el, store); el.setAttribute(a, next); }
    });
  }
  function walk(root) {
    if (root.nodeType === 3) { doText(root); return; }
    if (root.nodeType !== 1 || SKIP[root.tagName]) return;
    doAttrs(root);
    for (var c = root.firstChild; c; c = c.nextSibling) walk(c);
  }
  function restore(root) {
    if (root.nodeType === 3) { if (orig.has(root)) { root.nodeValue = orig.get(root); orig.delete(root); } return; }
    if (root.nodeType !== 1) return;
    var st = origAttr.get(root);
    if (st) { Object.keys(st).forEach(function (a) { root.setAttribute(a, st[a]); }); origAttr.delete(root); }
    for (var c = root.firstChild; c; c = c.nextSibling) restore(c);
  }

  var listeners = [];
  var titleLat = null;
  var observer = new MutationObserver(function (muts) {
    if (lang !== "cyr" || busy) return;
    busy = true;
    try {
      muts.forEach(function (m) {
        if (m.type === "characterData") doText(m.target);
        else if (m.type === "attributes") doAttrs(m.target);
        else m.addedNodes.forEach(walk);
      });
      if (document.title && titleLat === null) { titleLat = document.title; }
      if (titleLat !== null) document.title = toCyr(titleLat);
    } finally { busy = false; }
  });

  function apply() {
    busy = true;
    try {
      document.documentElement.lang = lang === "cyr" ? "uz-Cyrl" : "uz-Latn";
      if (lang === "cyr") {
        if (titleLat === null) titleLat = document.title;
        walk(document.body); document.title = toCyr(titleLat);
      } else {
        restore(document.body);
        if (titleLat !== null) document.title = titleLat;
      }
    } finally { busy = false; }
    var btns = document.querySelectorAll("[data-lang]");
    btns.forEach(function (b) {
      var on = b.getAttribute("data-lang") === lang;
      b.className = "px-2.5 py-1 text-[11px] font-bold rounded-md transition " + (on ? "bg-indigo-600 text-white" : "text-slate-300 hover:bg-slate-700");
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  function setLang(l) {
    lang = l === "cyr" ? "cyr" : "lat";
    try { localStorage.setItem(KEY, lang); } catch (e) {}
    apply();
    listeners.forEach(function (f) { try { f(lang); } catch (e) {} });
  }

  // alert/confirm oynalari ham tanlangan yozuvda chiqsin
  ["confirm", "alert", "prompt"].forEach(function (fn) {
    var o = window[fn];
    window[fn] = function (msg) {
      var a = Array.prototype.slice.call(arguments);
      if (lang === "cyr" && typeof msg === "string") a[0] = toCyr(msg);
      return o.apply(window, a);
    };
  });

  function buildSwitch() {
    var box = document.createElement("div");
    box.className = "inline-flex items-center gap-0.5 p-0.5 rounded-lg bg-slate-800/80 border border-slate-700";
    box.setAttribute("data-nt", "1");
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", "Til / Тил");
    [["lat", "Lotin"], ["cyr", "Кирилл"]].forEach(function (p) {
      var b = document.createElement("button");
      b.type = "button"; b.setAttribute("data-lang", p[0]); b.textContent = p[1];
      b.addEventListener("click", function () { setLang(p[0]); });
      box.appendChild(b);
    });
    var slot = document.getElementById("langSlot");
    if (slot) slot.appendChild(box);
    else { box.style.cssText = "position:fixed;top:8px;right:8px;z-index:60"; document.body.appendChild(box); }
  }

  function init() {
    buildSwitch();
    observer.observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
    apply();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();

  window.HGLang = {
    get: function () { return lang; },
    set: setLang,
    t: function (s) { return lang === "cyr" ? toCyr(s) : s; },  // canvas/grafik matnlari uchun
    onChange: function (f) { listeners.push(f); }
  };
})();
