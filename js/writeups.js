document.addEventListener("DOMContentLoaded", async function () {
  const writeupsContainer = document.getElementById("writeups-container");
  const categoryFilter = document.getElementById("category-filter");
  const difficultyFilter = document.getElementById("difficulty-filter");

  try {
    const response = await fetch("files/writeups.json");
    const writeups = await response.json();

    // Get unique categories and difficulties
    const categories = [...new Set(writeups.map(w => w.category))];
    const difficulties = [...new Set(writeups.map(w => w.difficulty))];

    // Populate category filter dropdown
    categories.forEach(category => {
      const option = document.createElement("option");
      option.value = category;
      option.textContent = category;
      categoryFilter.appendChild(option);
    });

    // Populate difficulty filter dropdown
    difficulties.forEach(difficulty => {
      const option = document.createElement("option");
      option.value = difficulty;
      option.textContent = difficulty;
      difficultyFilter.appendChild(option);
    });

    // Function to display filtered writeups
    function displayWriteups() {
      const selectedCategory = categoryFilter.value;
      const selectedDifficulty = difficultyFilter.value;

      writeupsContainer.innerHTML = ""; // Clear existing content

      const filteredWriteups = writeups.filter(w =>
        (selectedCategory === "all" || w.category === selectedCategory) &&
        (selectedDifficulty === "all" || w.difficulty === selectedDifficulty)
      );

      if (filteredWriteups.length === 0) {
        writeupsContainer.innerHTML = "<p>No writeups found for the selected filters.</p>";
        return;
      }

      filteredWriteups.forEach((writeup, index) => {
        const writeupCard = document.createElement("div");
        writeupCard.classList.add("writeup-card");
        writeupCard.setAttribute("data-aos", "fade-up"); // Add AOS animation
        writeupCard.setAttribute("data-aos-duration", "1000");
        writeupCard.setAttribute("data-aos-delay", `${index * 100}`); // Delay each card slightly

        writeupCard.innerHTML = `
          <a href="${writeup.link}" class="writeup-link">
            <img src="${writeup.image}" alt="${writeup.title}" class="writeup-img">
            <div class="writeup-info">
              <h3>${writeup.title}</h3>
              <p><strong>Category:</strong> ${writeup.category}</p>
              <p><strong>Difficulty:</strong> ${writeup.difficulty}</p>
              <p><strong>Date:</strong> ${new Date(writeup.date).toDateString()}</p>
              <p class="writeup-desc">${writeup.description}</p>
            </div>
          </a>
        `;
        writeupsContainer.appendChild(writeupCard);
      });

      AOS.refresh(); // Reinitialize AOS to recognize new elements
    }

    // Initial display
    displayWriteups();

    // Event listeners for filtering
    categoryFilter.addEventListener("change", displayWriteups);
    difficultyFilter.addEventListener("change", displayWriteups);

  } catch (error) {
    console.error("Error loading writeups:", error);
    writeupsContainer.innerHTML = "<p>Failed to load writeups.</p>";
  }
});