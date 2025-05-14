document.addEventListener("DOMContentLoaded", async function () {
  const writeupsContainer = document.getElementById("writeups-container");
  const categoryFilter = document.getElementById("category-filter");
  const difficultyFilter = document.getElementById("difficulty-filter");
  const platformFilter = document.getElementById("platform-filter");
  const platformButtons = document.querySelectorAll(".platform-filter-btn");

  let allWriteups = [];

  try {
    const response = await fetch("files/writeups.json");
    const data = await response.json();

    // Flatten writeups into a single array and add `platform` field
    for (const platform in data.platforms) {
      const platformWriteups = data.platforms[platform].map(w => ({
        ...w,
        platform
      }));
      allWriteups.push(...platformWriteups);
    }

    // Get unique categories and difficulties
    const categories = [...new Set(allWriteups.map(w => w.category))];
    const difficulties = [...new Set(allWriteups.map(w => w.difficulty))];

    // Populate category filter
    categories.forEach(category => {
      const option = document.createElement("option");
      option.value = category;
      option.textContent = category;
      categoryFilter.appendChild(option);
    });

    // Populate difficulty filter
    difficulties.forEach(difficulty => {
      const option = document.createElement("option");
      option.value = difficulty;
      option.textContent = difficulty;
      difficultyFilter.appendChild(option);
    });

    // Display filtered writeups
    function displayWriteups() {
      const selectedCategory = categoryFilter.value;
      const selectedDifficulty = difficultyFilter.value;
      const selectedPlatform = platformFilter.value;

      writeupsContainer.innerHTML = "";

      const filtered = allWriteups.filter(w =>
        (selectedCategory === "all" || w.category === selectedCategory) &&
        (selectedDifficulty === "all" || w.difficulty === selectedDifficulty) &&
        (selectedPlatform === "all" || w.platform === selectedPlatform)
      );

      if (filtered.length === 0) {
        writeupsContainer.innerHTML = "<p>No writeups found for the selected filters.</p>";
        return;
      }

      filtered.forEach((writeup, index) => {
        const card = document.createElement("div");
        card.classList.add("writeup-card");
        card.setAttribute("data-aos", "fade-up");
        card.setAttribute("data-aos-duration", "1000");
        card.setAttribute("data-aos-delay", `${index * 100}`);

        card.innerHTML = `
          <a href="${writeup.link}" class="writeup-link">
            <img src="${writeup.image}" alt="${writeup.title}" class="writeup-img">
            <div class="writeup-info">
              <h3>${writeup.title}</h3>
              <p><strong>Platform:</strong> ${writeup.platform}</p>
              <p><strong>Category:</strong> ${writeup.category}</p>
              <p><strong>Difficulty:</strong> ${writeup.difficulty}</p>
              <p><strong>Date:</strong> ${new Date(writeup.date).toDateString()}</p>
              <p class="writeup-desc">${writeup.description}</p>
            </div>
          </a>
        `;
        writeupsContainer.appendChild(card);
      });

      AOS.refresh();
    }

    // Initial render
    displayWriteups();

    // Dropdown filter listeners
    categoryFilter.addEventListener("change", displayWriteups);
    difficultyFilter.addEventListener("change", displayWriteups);
    platformFilter.addEventListener("change", displayWriteups);

    // Icon button platform filters
    platformButtons.forEach(button => {
      button.addEventListener("click", () => {
        const platform = button.getAttribute("data-platform");
        platformFilter.value = platform;
        displayWriteups();
      });
    });

  } catch (error) {
    console.error("Error loading writeups:", error);
    writeupsContainer.innerHTML = "<p>Failed to load writeups.</p>";
  }
});
