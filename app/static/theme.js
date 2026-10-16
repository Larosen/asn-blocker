// Applies the saved theme before the first paint so dark/OLED pages do not flash white.
try {
  const v = localStorage.getItem("asnb-theme");
  if (v === "light" || v === "dark" || v === "oled") document.documentElement.dataset.theme = v;
} catch { /* private mode: follow the system */ }
