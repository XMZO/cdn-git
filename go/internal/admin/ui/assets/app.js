(() => {
  const qs = (sel, root = document) => root.querySelector(sel);

  const formatJson = (ta, msgEl) => {
    if (!ta) return;
    const raw = (ta.value || "").trim();
    if (!raw) return;
    try {
      const v = JSON.parse(raw);
      ta.value = JSON.stringify(v, null, 2);
      if (msgEl) msgEl.textContent = "已格式化";
    } catch (e) {
      if (msgEl) {
        msgEl.textContent =
          "JSON 无效：" + (e && e.message ? e.message : "parse error");
      }
    }
  };

  const onFormatJsonClick = (e) => {
    const btn = e.target instanceof HTMLElement ? e.target.closest("[data-format-json]") : null;
    if (!btn) return;

    const sel = (btn.getAttribute("data-format-json") || "").trim();
    const row = btn.closest(".field");
    const msg = row ? qs(".json-msg", row) : null;
    const ta = sel ? qs(sel) : row ? row.querySelector("textarea") : null;

    if (ta instanceof HTMLTextAreaElement) {
      formatJson(ta, msg);
    }
  };

  const onTogglePassword = (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (!el.matches("[data-toggle-password]")) return;

    const targetSel = (el.getAttribute("data-toggle-password") || "").trim();
    const input = targetSel ? qs(targetSel) : null;
    if (!(input instanceof HTMLInputElement)) return;

    input.type = el.checked ? "text" : "password";
  };

  document.addEventListener("click", onFormatJsonClick);
  document.addEventListener("change", onTogglePassword);

  window.HazukiUI = { qs, formatJson };
})();

