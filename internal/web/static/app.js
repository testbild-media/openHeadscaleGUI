// OpenHeadscaleGUI – small progressive enhancements (CSP: script-src 'self').
(function () {
  "use strict";

  // Confirmation for destructive forms: <form data-confirm="...">
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (f && f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) {
      e.preventDefault();
    }
  }, true);

  // Copy buttons: <button data-copy="#id"> or data-copy-text="..."
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("[data-copy],[data-copy-text]") : null;
    if (!b) return;
    e.preventDefault();
    var text = b.getAttribute("data-copy-text");
    if (text === null) {
      var el = document.querySelector(b.getAttribute("data-copy"));
      text = el ? (el.value !== undefined && el.tagName !== "DIV" && el.tagName !== "PRE" ? el.value : el.textContent) : "";
    }
    var done = function () {
      var old = b.textContent;
      b.textContent = "Kopiert ✓";
      setTimeout(function () { b.textContent = old; }, 1400);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text.trim()).then(done, function () {});
    } else {
      var ta = document.createElement("textarea");
      ta.value = text.trim();
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } catch (err) {}
      document.body.removeChild(ta);
    }
  });

  // Show/hide fields depending on a select: <select data-switch="name"> and
  // <div data-show-for="name:value1,value2">
  function applySwitch(sel) {
    var name = sel.getAttribute("data-switch");
    var val = sel.type === "checkbox" ? (sel.checked ? "on" : "off") : sel.value;
    document.querySelectorAll("[data-show-for]").forEach(function (el) {
      var spec = el.getAttribute("data-show-for").split(":");
      if (spec[0] !== name) return;
      var show = spec[1].split(",").indexOf(val) >= 0;
      el.classList.toggle("hidden", !show);
      el.querySelectorAll("input,select,textarea").forEach(function (i) { i.disabled = !show; });
    });
  }
  document.querySelectorAll("[data-switch]").forEach(function (sel) {
    sel.addEventListener("change", function () { applySwitch(sel); });
    applySwitch(sel);
  });

  // Fill an input from a select: <select data-fill="#target">
  document.querySelectorAll("[data-fill]").forEach(function (sel) {
    sel.addEventListener("change", function () {
      var t = document.querySelector(sel.getAttribute("data-fill"));
      if (t && sel.value) t.value = sel.value;
    });
  });

  // Live refresh: elements with id and data-live="seconds" are reloaded
  // from the same URL while the tab is visible.
  var live = document.querySelectorAll("[data-live][id]");
  if (live.length) {
    var interval = parseInt(live[0].getAttribute("data-live"), 10) || 10;
    var busy = false;
    setInterval(function () {
      if (document.hidden || busy) return;
      var active = document.activeElement;
      if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT")) return;
      busy = true;
      fetch(window.location.href, { credentials: "same-origin", headers: { "X-Requested-With": "ohg-live" } })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) {
          if (!html) return;
          var doc = new DOMParser().parseFromString(html, "text/html");
          live.forEach(function (el) {
            var fresh = doc.getElementById(el.id);
            if (fresh) el.innerHTML = fresh.innerHTML;
          });
        })
        .catch(function () {})
        .finally(function () { busy = false; });
    }, interval * 1000);
  }

  // Select contents of code blocks on double click
  document.querySelectorAll(".code").forEach(function (el) {
    el.addEventListener("dblclick", function () {
      var r = document.createRange();
      r.selectNodeContents(el);
      var s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
    });
  });
})();
