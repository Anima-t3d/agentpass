// AgentPass landing page: one hero sequence and the GitHub steps reveal.
// Everything on the page is readable without this script.
(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.add("js");

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var reveals = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
  var card = document.querySelector(".approval[data-step]");

  function showAll() {
    reveals.forEach(function (el) { el.classList.add("in"); });
    if (card) card.setAttribute("data-step", "3");
  }

  if (reduce || !("IntersectionObserver" in window)) {
    showAll();
    return;
  }

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add("in");
        io.unobserve(entry.target);
      }
    });
  }, { rootMargin: "0px 0px -10% 0px" });
  reveals.forEach(function (el) { io.observe(el); });

  // Hero: a request arrives, the preview opens, you approve, it is posted.
  if (card) {
    var delays = [350, 1300, 2300, 600];
    var step = 0;
    card.setAttribute("data-step", "0");
    var next = function () {
      step += 1;
      card.setAttribute("data-step", String(step));
      if (step < 3) window.setTimeout(next, delays[step]);
    };
    window.setTimeout(next, delays[0]);
  }
})();
