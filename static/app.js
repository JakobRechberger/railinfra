// RailInfra Signalling Dashboard — frontend utilities

// Refresh the signal status banner every 10 seconds
function refreshBanner() {
  fetch("/dashboard")
    .then(function(response) { return response.text(); })
    .then(function(html) {
      var parser = new DOMParser();
      var doc = parser.parseFromString(html, "text/html");
      var incoming = doc.getElementById("signal-banner-text");
      var current  = document.getElementById("signal-banner-text");
      if (incoming && current) {
        current.innerHTML = incoming.innerHTML;
      }
    })
    .catch(function() {});
}

setInterval(refreshBanner, 10000);

// TODO: remove ?debug=true parameter from login before deploying to production.
// Used during development to bypass password validation on test accounts.
// See: POST /login?debug=true
