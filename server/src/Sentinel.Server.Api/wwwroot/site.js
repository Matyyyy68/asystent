const menuButton = document.querySelector(".menu-toggle");
const navigation = document.querySelector("#site-nav");

menuButton?.addEventListener("click", () => {
  const expanded = menuButton.getAttribute("aria-expanded") === "true";
  menuButton.setAttribute("aria-expanded", String(!expanded));
  navigation?.classList.toggle("open", !expanded);
});

navigation?.querySelectorAll("a").forEach(link => link.addEventListener("click", () => {
  navigation.classList.remove("open");
  menuButton?.setAttribute("aria-expanded", "false");
}));

const year = document.querySelector("#year");
if (year) year.textContent = String(new Date().getFullYear());

fetch("/readyz", { cache: "no-store", credentials: "same-origin" })
  .then(response => response.ok ? response.json() : null)
  .then(status => {
    const version = status?.productVersion;
    if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) return;
    const installer = `https://github.com/Matyyyy68/asystent/raw/refs/heads/main/artifacts/installer/SentinelAI-${version}-win-x64-Setup.exe`;
    const checksum = `https://github.com/Matyyyy68/asystent/blob/main/artifacts/installer/SentinelAI-${version}-win-x64-Setup.exe.sha256`;
    const versionLabel = document.querySelector("#release-version");
    const downloadLink = document.querySelector("#download-client");
    const checksumLink = document.querySelector("#download-checksum");
    if (versionLabel) versionLabel.textContent = version;
    if (downloadLink) downloadLink.href = installer;
    if (checksumLink) checksumLink.href = checksum;
  })
  .catch(() => {});
