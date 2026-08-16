const params = new URLSearchParams(location.search);
const url = params.get("url") || "";
document.getElementById("reason").textContent =
  params.get("reason") || "This page looked dangerous.";
document.getElementById("url").textContent = url;
document.getElementById("back").addEventListener("click", (e) => {
  e.preventDefault(); history.length > 1 ? history.back() : window.close();
});
document.getElementById("anyway").addEventListener("click", () => {
  if (confirm("Open this page anyway?\n\nWe blocked it because it looked dangerous.")) {
    location.replace(url);
  }
});
