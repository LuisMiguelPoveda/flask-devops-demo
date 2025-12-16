(function () {
  console.log("[nav] nav.js cargado"); // ✅ para comprobar que se ejecuta

  const navContainers = Array.from(document.querySelectorAll("[data-nav]"));
  if (!navContainers.length) {
    console.log("[nav] No hay contenedores [data-nav] en esta página");
    return;
  }

  function getOptions(container) {
    return Array.from(container.querySelectorAll(".nav-option"));
  }

  function clearSelected(options) {
    options.forEach((el) => el.classList.remove("is-selected"));
  }

  function selectIndex(container, idx) {
    const options = getOptions(container);
    if (!options.length) return;

    const clamped = Math.max(0, Math.min(idx, options.length - 1));
    clearSelected(options);

    const el = options[clamped];
    el.classList.add("is-selected");

    // Foco para que Enter funcione
    if (typeof el.focus === "function") {
      el.focus({ preventScroll: true });
    }

    el.scrollIntoView({ block: "nearest" });
  }

  function initContainer(container) {
    const options = getOptions(container);
    if (!options.length) return;

    options.forEach((el) => {
      if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "0");

      el.addEventListener("mouseenter", () => {
        const opts = getOptions(container);
        const idx = opts.indexOf(el);
        if (idx >= 0) selectIndex(container, idx);
      });

      el.addEventListener("focus", () => {
        const opts = getOptions(container);
        const idx = opts.indexOf(el);
        if (idx >= 0) selectIndex(container, idx);
      });
    });

    const existing = options.findIndex((el) => el.classList.contains("is-selected"));
    selectIndex(container, existing >= 0 ? existing : 0);

    container._navActive = true;

    container.addEventListener("pointerdown", () => {
      navContainers.forEach((c) => (c._navActive = false));
      container._navActive = true;
    });

    container.addEventListener("focusin", () => {
      navContainers.forEach((c) => (c._navActive = false));
      container._navActive = true;
    });
  }

  navContainers.forEach(initContainer);

  document.addEventListener("keydown", (e) => {
    const tag = (document.activeElement && document.activeElement.tagName) || "";
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(tag);
    if (typing) return;

    const activeContainer = navContainers.find((c) => c._navActive) || navContainers[0];
    const options = getOptions(activeContainer);
    if (!options.length) return;

    const currentIdx = options.findIndex((el) => el.classList.contains("is-selected"));
    const idx = currentIdx >= 0 ? currentIdx : 0;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectIndex(activeContainer, idx + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectIndex(activeContainer, idx - 1);
    } else if (e.key === "Enter") {
      const el = options[idx];
      if (!el) return;

      e.preventDefault();
      if (typeof el.click === "function") el.click();
    }
  });
})();
