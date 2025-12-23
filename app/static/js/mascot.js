(function () {
  const root = document.getElementById("mascot-root");
  if (!root) return;
  const justLoggedIn = (document.body.dataset.justLoggedIn || "") === "1";
  const justRegistered = (document.body.dataset.justRegistered || "") === "1";
  const profeBusy = (document.body.dataset.profeBusy || "") === "1";
  const currentPage = document.body.dataset.page || "";

  const img = root.querySelector("[data-mascot-img]");
  const bubble = root.querySelector("[data-mascot-bubble]");
  const card = root.querySelector("[data-mascot-card]");
  const cardText = root.querySelector("[data-mascot-card-text]");

  // Paths where you should place your GIF/WebP files
  const idleSprites =
    currentPage === "ask_profe"
      ? ["/static/img/mascot/profe.gif"]
      : ["/static/img/mascot/idle1.gif", "/static/img/mascot/idle2.gif", "/static/img/mascot/idle3.gif"];
  const actions = {
    celebrate: "/static/img/mascot/celebrate.gif",
  };
  const angrySprites = [
    "/static/img/mascot/angry1.gif",
    "/static/img/mascot/angry2.gif",
    "/static/img/mascot/angry3.gif",
  ];

  const idleTips =
    currentPage === "ask_profe"
      ? [
          "Estoy aquí para ayudarte, pregúntame con confianza.",
          "Si algo no queda claro, dime y lo explico de otra forma.",
          "Respira hondo, vamos paso a paso con tus dudas.",
          "Cuéntame qué tema quieres reforzar y lo vemos juntos.",
        ]
      : [
          "Tip: Genera 5 flashcards desde un apunte en segundos.",
          "Recuerda revisar tus flashcards antes del examen.",
          "Los apuntes más recientes aparecen arriba en las listas.",
          "Puedes editar un deck y añadir más tarjetas cuando quieras.",
        ];

  // State/timers for idle loop, tooltips, and one-shot actions (celebrate/angry).
  let idleTimer = null;
  let tipTimer = null;
  let revertTimer = null;
  let currentAction = null;
  let hideTimer = null;
  let currentTip = null; // "bubble" | "card" | null

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function hideTip() {
    if (hideTimer) clearTimeout(hideTimer);
    if (currentTip === "bubble" && bubble) {
      bubble.classList.remove("is-visible", "is-success", "is-error");
      bubble.hidden = true;
    }
    if (currentTip === "card" && card) {
      card.classList.remove("is-visible", "is-success", "is-error");
      card.hidden = true;
    }
    currentTip = null;
  }

  function showTip({ variant, message, duration, tone }) {
    if (currentTip) return;
    const text = message || pick(idleTips);
    if (variant === "card") {
      if (!card || !cardText) return;
      cardText.textContent = text;
      card.hidden = false;
      card.classList.add("is-visible");
      if (tone === "success") card.classList.add("is-success");
      if (tone === "error") card.classList.add("is-error");
      currentTip = "card";
    } else {
      if (!bubble) return;
      bubble.textContent = text;
      bubble.hidden = false;
      bubble.classList.add("is-visible");
      if (tone === "success") bubble.classList.add("is-success");
      if (tone === "error") bubble.classList.add("is-error");
      currentTip = "bubble";
    }

    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      hideTip();
      scheduleTip(180000);
    }, duration);
  }

  function setIdleSprite() {
    if (!img) return;
    const src = pick(idleSprites);
    img.src = src;
    currentAction = null;
  }

  function startIdleLoop() {
    setIdleSprite();
    if (idleTimer) clearInterval(idleTimer);
    idleTimer = setInterval(setIdleSprite, 12000);
  }

  function scheduleTip(delay = 4000) {
    if (tipTimer) clearTimeout(tipTimer);
    tipTimer = setTimeout(() => {
      if (currentAction || currentTip) {
        scheduleTip(2000);
        return;
      }
      const variant = Math.random() < 0.5 ? "bubble" : "card";
      const duration = variant === "card" ? 14400 : 11400;
      showTip({ variant, duration });
    }, delay);
  }

  function trigger(action, opts = {}) {
    if (!img) return;
    if (currentAction) return; // evita solapado de acciones
    const src = actions[action];
    if (!src) return;
    currentAction = action;
    if (idleTimer) clearInterval(idleTimer);
    img.src = src;

    if (opts.text) {
      showTip({ variant: "bubble", message: opts.text, duration: 11400 });
    }

    if (revertTimer) clearTimeout(revertTimer);
    revertTimer = setTimeout(() => {
      setIdleSprite();
      startIdleLoop();
    }, opts.duration || 4200);
  }

  function detectLoginSuccess() {
    const successFlash = document.querySelector(".flash--login_success");
    if (successFlash || justLoggedIn || justRegistered) {
      trigger("celebrate", { text: justRegistered ? "Cuenta creada, ¡bienvenido!" : "Sesión iniciada, ¡bienvenido!" });
      setTimeout(() => {
        if (!currentAction && !currentTip) {
          showTip({ variant: "bubble", message: "¡Listo para estudiar! Revisa tus flashcards.", duration: 11400 });
        }
      }, 1500);
    }
  }

  function scheduleProfeBusyNotice(triesLeft = 20, delay = 1200) {
    if (!profeBusy || currentPage !== "dashboard") return;
    if (triesLeft <= 0) return;
    setTimeout(() => {
      if (currentAction || currentTip) {
        scheduleProfeBusyNotice(triesLeft - 1, 1500);
        return;
      }
      showTip({
        variant: "bubble",
        message: "Ahora mismo el profe está ocupado procesando trabajos. Cuando termine, podrás usar «Pregúntale al profe».",
        duration: 12000,
        tone: "error",
      });
    }, delay);
  }

  async function pollJobUpdates() {
    try {
      const resp = await fetch("/api/jobs/updates");
      if (!resp.ok) return;
      const data = await resp.json();
      (data.jobs || []).forEach((j) => {
        hideTip();
        const tone = j.status === "success" ? "success" : "error";
        showTip({
          variant: "card",
          message: j.message || (j.status === "success" ? "Trabajo finalizado" : "Trabajo con error"),
          duration: 12000,
          tone,
        });
      });
    } catch (e) {
      // ignora errores de red
    }
  }

  // Start loops
  startIdleLoop();
  scheduleTip();
  detectLoginSuccess();
  scheduleProfeBusyNotice();
  pollJobUpdates();
  setInterval(pollJobUpdates, 8000);

  // Permitir que el usuario moleste a la mascota
  if (root && img) {
    root.addEventListener("click", (e) => {
      // evita que otros clics de la UI burbujeen
      e.stopPropagation();
      if (currentAction) return;
      const angry = pick(angrySprites);
      if (angry) {
        actions.angry = angry;
        trigger("angry", { duration: 3000 });
      }
    });
  }

  // Pause loops when tab hidden to save CPU
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (idleTimer) clearInterval(idleTimer);
      if (tipTimer) clearTimeout(tipTimer);
      if (hideTimer) clearTimeout(hideTimer);
    } else {
      startIdleLoop();
      scheduleTip();
    }
  });
})();
