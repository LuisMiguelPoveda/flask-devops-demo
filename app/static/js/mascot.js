(function () {
  const root = document.getElementById("mascot-root");
  if (!root) return;

  const img = root.querySelector("[data-mascot-img]");
  const bubble = root.querySelector("[data-mascot-bubble]");
  const card = root.querySelector("[data-mascot-card]");
  const cardText = root.querySelector("[data-mascot-card-text]");

  // Paths where you should place your GIF/WebP files
  const idleSprites = [
    "/static/img/mascot/idle1.gif",
    "/static/img/mascot/idle2.gif",
    "/static/img/mascot/idle3.gif",
  ];
  const actions = {
    celebrate: "/static/img/mascot/celebrate.gif",
  };

  const idleTips = [
    "Tip: Genera 5 flashcards desde un apunte en segundos.",
    "Recuerda revisar tus flashcards antes del examen.",
    "Los apuntes más recientes aparecen arriba en las listas.",
    "Puedes editar un deck y añadir más tarjetas cuando quieras.",
  ];

  let idleTimer = null;
  let tipTimer = null;
  let revertTimer = null;
  let currentAction = null;
  let cardTimer = null;
  let bubbleVisible = false;
  let cardVisible = false;

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function showBubble(message) {
    if (!bubble) return;
    if (bubbleVisible) return;
    bubble.textContent = message;
    bubble.hidden = false;
    bubble.classList.add("is-visible");
    bubbleVisible = true;
    setTimeout(() => {
      bubble.classList.remove("is-visible");
      bubble.hidden = true;
      bubbleVisible = false;
    }, 11400);
  }

  function showCardTip(message) {
    if (!card || !cardText) return;
    if (cardVisible) return;
    cardText.textContent = message;
    card.hidden = false;
    card.classList.add("is-visible");
    cardVisible = true;
    setTimeout(() => {
      card.classList.remove("is-visible");
      card.hidden = true;
      cardVisible = false;
    }, 14400);
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

  function startTipLoop() {
    if (tipTimer) clearInterval(tipTimer);
    // primer tip rápido
    setTimeout(() => {
      if (!currentAction) showBubble(pick(idleTips));
    }, 4000);
    tipTimer = setInterval(() => {
      if (currentAction) return;
      showBubble(pick(idleTips));
    }, 15000);
  }

  function startCardLoop() {
    if (cardTimer) clearInterval(cardTimer);
    // primer card temprano
    setTimeout(() => {
      if (!currentAction) showCardTip(pick(idleTips));
    }, 9000);
    cardTimer = setInterval(() => {
      if (currentAction) return;
      showCardTip(pick(idleTips));
    }, 20000);
  }

  function trigger(action, opts = {}) {
    if (!img) return;
    const src = actions[action];
    if (!src) return;
    currentAction = action;
    if (idleTimer) clearInterval(idleTimer);
    img.src = src;

    if (opts.text) {
      showBubble(opts.text);
    }

    if (revertTimer) clearTimeout(revertTimer);
    revertTimer = setTimeout(() => {
      setIdleSprite();
      startIdleLoop();
    }, opts.duration || 4200);
  }

  function detectLoginSuccess() {
    const successFlash = document.querySelector(".flash--login_success");
    if (successFlash) {
      trigger("celebrate", { text: "Sesión iniciada, ¡bienvenido!" });
      // Garantiza también un tip destacado al entrar al dashboard tras login
      setTimeout(() => {
        if (!currentAction) {
          showBubble("¡Listo para estudiar! Revisa tus flashcards.");
        }
      }, 1500);
    }
  }

  // Start loops
  startIdleLoop();
  startTipLoop();
  startCardLoop();
  detectLoginSuccess();

  // Pause loops when tab hidden to save CPU
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (idleTimer) clearInterval(idleTimer);
      if (tipTimer) clearInterval(tipTimer);
      if (cardTimer) clearInterval(cardTimer);
    } else {
      startIdleLoop();
      startTipLoop();
      startCardLoop();
    }
  });
})();
