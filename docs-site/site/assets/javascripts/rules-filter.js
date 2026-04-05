// Client-side search/filter for the built-in rules table
document.addEventListener("DOMContentLoaded", function () {
  const input = document.querySelector(".rules-search");
  if (!input) return;

  const table = document.querySelector(".rules-table");
  if (!table) return;

  const rows = Array.from(table.querySelectorAll("tbody tr"));
  const countEl = document.querySelector(".rules-count");
  const total = rows.length;

  function updateCount(visible) {
    if (countEl) {
      countEl.textContent = "Showing " + visible + " of " + total + " rules";
    }
  }

  let debounceTimer;
  input.addEventListener("input", function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      const query = input.value.toLowerCase().trim();
      let visible = 0;

      rows.forEach(function (row) {
        const text = row.textContent.toLowerCase();
        const match = !query || text.indexOf(query) !== -1;
        row.style.display = match ? "" : "none";
        if (match) visible++;
      });

      updateCount(visible);
    }, 150);
  });

  updateCount(total);
});
