// Small progressive enhancements. Every page works without this file.
(function () {
  "use strict";

  function store() {
    try { return window.localStorage; } catch (e) { return null; }
  }

  // Form memory: fields marked data-remember keep their last value in this
  // browser. Password fields and secrets are never stored.
  function remember(form) {
    var id = form.getAttribute("data-remember-form");
    var ls = store();
    if (!id || !ls) return;
    var fields = form.querySelectorAll("[data-remember]");
    var key = function (el) { return "vpsc:" + id + ":" + el.name; };
    if (!form.hasAttribute("data-prefilled")) {
      fields.forEach(function (el) {
        if (el.type === "password") return;
        var saved;
        try { saved = ls.getItem(key(el)); } catch (e) { return; }
        if (saved === null) return;
        if (el.type === "radio") el.checked = (el.value === saved);
        else if (el.type === "checkbox") el.checked = (saved === "1");
        else el.value = saved;
      });
    }
    fields.forEach(function (el) {
      if (el.type === "password") return;
      el.addEventListener("change", function () {
        var value = el.type === "checkbox" ? (el.checked ? "1" : "0") : el.value;
        if (el.type === "radio" && !el.checked) return;
        try { ls.setItem(key(el), value); } catch (e) { /* storage full or blocked */ }
      });
    });
  }

  // Show fields that depend on a radio choice: data-show="group=value".
  function toggles(root) {
    var update = function () {
      root.querySelectorAll("[data-show]").forEach(function (el) {
        var parts = el.getAttribute("data-show").split("=");
        var checked = root.querySelector('input[data-toggle="' + parts[0] + '"]:checked');
        el.hidden = !(checked && checked.value === parts[1]);
      });
    };
    root.querySelectorAll("input[data-toggle]").forEach(function (el) {
      el.addEventListener("change", update);
    });
    update();
  }

  function copyButtons(root) {
    root.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = document.querySelector(btn.getAttribute("data-copy"));
        if (!target) return;
        var text = target.innerText;
        var done = function () {
          var old = btn.textContent;
          btn.textContent = "✓";
          setTimeout(function () { btn.textContent = old; }, 1500);
        };
        if (navigator.clipboard) {
          navigator.clipboard.writeText(text).then(done, function () { selectText(target); });
        } else {
          selectText(target);
        }
      });
    });
  }

  function selectText(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  function confirms(root) {
    root.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        if (!window.confirm(form.getAttribute("data-confirm"))) ev.preventDefault();
      });
    });
  }

  function busyButtons(root) {
    root.querySelectorAll("form.stack").forEach(function (form) {
      form.addEventListener("submit", function () {
        var btn = form.querySelector("button.primary");
        if (btn) { btn.disabled = true; btn.classList.add("busy"); }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("form[data-remember-form]").forEach(remember);
    toggles(document);
    copyButtons(document);
    confirms(document);
    busyButtons(document);
  });
})();
