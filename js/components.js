// components.js - Loads navbar & footer dynamically

// Function to load an external HTML file into an element
function loadComponent(url, elementId) {
    fetch(url)
      .then(response => response.text())
      .then(data => {
        document.getElementById(elementId).innerHTML = data;
      })
      .catch(error => console.error(`Error loading ${url}:`, error));
  }
  
  // Load Navbar
  document.addEventListener("DOMContentLoaded", () => {
    loadComponent("../components/nav.html", "nav-placeholder");
    loadComponent("../components/footer.html", "footer-placeholder");
  });