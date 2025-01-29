document.addEventListener("DOMContentLoaded", async function () {
  const writeupsContainer = document.getElementById("writeups-container");

  try {
    const response = await fetch("files/writeups.json");
    const writeups = await response.json();

    writeups.forEach((writeup, index) => {
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
  } catch (error) {
    console.error("Error loading writeups:", error);
    writeupsContainer.innerHTML = "<p>Failed to load writeups.</p>";
  }
});