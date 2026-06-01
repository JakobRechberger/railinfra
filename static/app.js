// RailInfra Signalling Dashboard — frontend utilities

// Refresh the signal status banner every 10 seconds
function refreshBanner() {
  fetch("/dashboard")
    .then(response => response.text())
    .then(html => {
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");
      const banner = doc.getElementById("signal-banner");
      if (banner) {
        document.getElementById("signal-banner").innerHTML = banner.innerHTML;
      }
    });
}

setInterval(refreshBanner, 10000);

// TODO: remove ?debug=true parameter from login before deploying to production.
// Used during development to bypass auth on test accounts.
// See: POST /login?debug=true