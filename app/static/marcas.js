document.addEventListener("DOMContentLoaded", () => {
  initReveal();
  initParallaxOrbs();
  initMagneticButtons();
  initCardGlow();
  initHeroTilt();
  initSmoothSectionHover();
  initReducedMotionSupport();
});

/* =========================
   REVEAL ELEGANTE
========================= */
function initReveal() {
  const elements = document.querySelectorAll(".m-reveal");
  if (!elements.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;

        const el = entry.target;
        el.classList.add("is-visible");
        observer.unobserve(el);
      });
    },
    {
      threshold: 0.14,
      rootMargin: "0px 0px -40px 0px",
    }
  );

  elements.forEach((el, i) => {
    const delay = el.classList.contains("m-reveal--delay") ? 180 : i * 40;
    el.style.transitionDelay = `${delay}ms`;
    observer.observe(el);
  });
}

/* =========================
   PARALLAX SUAVE EN ORBES
========================= */
function initParallaxOrbs() {
  const orbOne = document.querySelector(".m-orb--one");
  const orbTwo = document.querySelector(".m-orb--two");

  if (!orbOne && !orbTwo) return;

  let mouseX = 0;
  let mouseY = 0;
  let currentX1 = 0;
  let currentY1 = 0;
  let currentX2 = 0;
  let currentY2 = 0;
  let rafId = null;

  document.addEventListener("mousemove", (e) => {
    const centerX = window.innerWidth / 2;
    const centerY = window.innerHeight / 2;

    mouseX = (e.clientX - centerX) / centerX;
    mouseY = (e.clientY - centerY) / centerY;
  });

  function animate() {
    currentX1 += (mouseX * 18 - currentX1) * 0.05;
    currentY1 += (mouseY * 18 - currentY1) * 0.05;

    currentX2 += (mouseX * -14 - currentX2) * 0.05;
    currentY2 += (mouseY * -14 - currentY2) * 0.05;

    if (orbOne) {
      orbOne.style.transform = `translate3d(${currentX1}px, ${currentY1}px, 0)`;
    }

    if (orbTwo) {
      orbTwo.style.transform = `translate3d(${currentX2}px, ${currentY2}px, 0)`;
    }

    rafId = window.requestAnimationFrame(animate);
  }

  animate();

  window.addEventListener("beforeunload", () => {
    if (rafId) cancelAnimationFrame(rafId);
  });
}

/* =========================
   BOTONES CON EFECTO MAGNÉTICO
========================= */
function initMagneticButtons() {
  const buttons = document.querySelectorAll(".m-btn");
  if (!buttons.length) return;

  buttons.forEach((button) => {
    button.addEventListener("mousemove", (e) => {
      const rect = button.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;

      button.style.transform = `translate(${x * 0.08}px, ${y * 0.08}px)`;
    });

    button.addEventListener("mouseleave", () => {
      button.style.transform = "translate(0, 0)";
    });
  });
}

/* =========================
   GLOW DINÁMICO EN TARJETAS
========================= */
function initCardGlow() {
  const cards = document.querySelectorAll(
    ".m-serviceCard, .m-docCard, .m-feature, .m-miniStats__item, .m-step__content, .m-trustBand__item, .m-heroCard"
  );

  if (!cards.length) return;

  cards.forEach((card) => {
    card.addEventListener("mouseenter", () => {
      card.classList.add("is-active");
    });

    card.addEventListener("mousemove", (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      card.style.setProperty("--mx", `${x}px`);
      card.style.setProperty("--my", `${y}px`);
    });

    card.addEventListener("mouseleave", () => {
      card.classList.remove("is-active");
    });
  });
}

/* =========================
   LEVE TILT EN HERO CARD
========================= */
function initHeroTilt() {
  const heroCard = document.querySelector(".m-heroCard");
  if (!heroCard) return;

  heroCard.addEventListener("mouseenter", () => {
    heroCard.classList.add("is-active");
  });

  heroCard.addEventListener("mousemove", (e) => {
    const rect = heroCard.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const rotateY = ((x / rect.width) - 0.5) * 8;
    const rotateX = ((y / rect.height) - 0.5) * -8;

    heroCard.style.transform = `
      perspective(1200px)
      rotateX(${rotateX}deg)
      rotateY(${rotateY}deg)
      translateY(-4px)
    `;
  });

  heroCard.addEventListener("mouseleave", () => {
    heroCard.classList.remove("is-active");
    heroCard.style.transform = `
      perspective(1200px)
      rotateX(0deg)
      rotateY(0deg)
      translateY(0px)
    `;
  });
}

/* =========================
   HOVER SUAVE EN BLOQUES GRANDES
========================= */
function initSmoothSectionHover() {
  const sections = document.querySelectorAll(".m-contact, .m-trustBand");
  if (!sections.length) return;

  sections.forEach((section) => {
    section.addEventListener("mousemove", (e) => {
      const rect = section.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 100;
      const y = ((e.clientY - rect.top) / rect.height) * 100;

      section.style.setProperty("--sx", `${x}%`);
      section.style.setProperty("--sy", `${y}%`);
    });
  });
}

/* =========================
   SOPORTE PARA REDUCED MOTION
========================= */
function initReducedMotionSupport() {
  const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (!mediaQuery.matches) return;

  document.querySelectorAll(".m-reveal").forEach((el) => {
    el.classList.add("is-visible");
    el.style.transition = "none";
    el.style.transform = "none";
    el.style.opacity = "1";
  });

  document.querySelectorAll(".m-btn, .m-heroCard").forEach((el) => {
    el.addEventListener("mousemove", () => {
      el.style.transform = "none";
    });
    el.addEventListener("mouseleave", () => {
      el.style.transform = "none";
    });
  });

  document.querySelectorAll(".m-orb").forEach((orb) => {
    orb.style.animation = "none";
    orb.style.transform = "none";
  });
}