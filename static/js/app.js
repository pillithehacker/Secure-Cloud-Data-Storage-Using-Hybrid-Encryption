$(function () {
  // DataTables setup:
  // - On File Manager + Activity Logs pages: use a compact custom toolbar.
  // - Elsewhere: keep the default controls.
  function initCompactToolbarDataTable($table) {
    const $existingToolbar = $table.prev(".table-toolbar");
    const dt = $table.DataTable({
      responsive: true,
      pageLength: 10,
      dom: "rtip" // Table + Info + Pagination, no built-in length/search
    });

    const $wrapper = $table.closest(".dataTables_wrapper");

    let $toolbar = $existingToolbar;
    if (!$toolbar || !$toolbar.length) {
      $toolbar = $(`
        <div class="table-toolbar">
          <div class="toolbar-left">
            <label>Show</label>
            <select class="compact-select">
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
            </select>
            <span>entries</span>
          </div>
          <div class="toolbar-right">
            <div class="compact-search-wrapper">
              <i class="fas fa-search compact-search-icon"></i>
              <input type="text" class="compact-search-input" placeholder="Search..." />
            </div>
          </div>
        </div>
      `);
      $wrapper.prepend($toolbar);
    }

    const $select = $toolbar.find("select.compact-select");
    const $search = $toolbar.find("input.compact-search-input");

    // Align dropdown with current DataTables page length.
    $select.val(dt.page.len());

    $select.on("change", function () {
      const len = parseInt($(this).val(), 10);
      dt.page.len(len).draw();
    });

    const applySearch = () => {
      dt.search($search.val()).draw();
    };
    $search.on("keyup change clear", applySearch);

    return dt;
  }

  $(".datatable").each(function () {
    const $t = $(this);
    const inFilesPage = $t.closest(".files-page").length > 0;
    const inLogsPage = $t.closest(".logs-page").length > 0;
    const hasPrebuiltToolbar = $t.prev(".table-toolbar").length > 0;

    if (inFilesPage || inLogsPage || hasPrebuiltToolbar) {
      initCompactToolbarDataTable($t);
    } else {
      $t.DataTable({
        responsive: true,
        pageLength: 8
      });
    }
  });

  if (window.AOS) AOS.init({ duration: 700, once: true });

  function mountChart(id, color) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    new Chart(canvas, {
      type: "line",
      data: {
        labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        datasets: [{
          label: "Activity",
          data: [3, 8, 5, 12, 9, 14, 11],
          borderColor: color,
          backgroundColor: "rgba(120, 170, 255, 0.15)",
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        plugins: { legend: { labels: { color: "#dbe7ff" } } },
        scales: {
          x: { ticks: { color: "#9cb4d8" } },
          y: { ticks: { color: "#9cb4d8" } }
        }
      }
    });
  }

  mountChart("activityChart", "#00d4ff");
  mountChart("userChart", "#8b5bff");
  mountChart("auditorChart", "#ff57c8");

  const quotes = Array.from(document.querySelectorAll(".hero-section .quote"));
  const dots = Array.from(document.querySelectorAll(".hero-section .dot"));
  if (quotes.length && dots.length) {
    let quoteIndex = 0;
    const setActiveQuote = (idx) => {
      quotes.forEach((q, i) => q.classList.toggle("active", i === idx));
      dots.forEach((d, i) => d.classList.toggle("active", i === idx));
    };
    setActiveQuote(0);
    setInterval(() => {
      quoteIndex = (quoteIndex + 1) % quotes.length;
      setActiveQuote(quoteIndex);
    }, 4000);
  }

  if (window.particlesJS && document.getElementById("particles-js")) {
    particlesJS("particles-js", {
      particles: {
        number: { value: 42 },
        color: { value: ["#00d4ff", "#8c52ff", "#ff48c4"] },
        size: { value: 2.5 },
        move: { speed: 1.2 },
        line_linked: { enable: true, opacity: 0.16 }
      }
    });
  }
  // Premium page transitions: apply staggered fade-up animations to the
  // current page content (cards, tables, panels) after DOM is ready.
  const pageRoot = document.querySelector(".page-transition");
  if (pageRoot) {
    const targets = pageRoot.querySelectorAll(
      ".glass-card, .dashboard-shell, table, .developer-grid, .timeline, .insight-card, .quote-slider"
    );
    targets.forEach((el, i) => {
      const delay = Math.min(i, 16) * 0.08;
      el.style.setProperty("--d", `${delay}s`);
      el.classList.add("fadeup-stagger");
    });
  }

  $(".delete-link").on("click", function (e) {
    e.preventDefault();
    const href = $(this).attr("href");
    Swal.fire({
      title: "Delete this file?",
      text: "You can restore from recycle bin in future versions.",
      icon: "warning",
      showCancelButton: true,
      confirmButtonText: "Yes, delete",
      background: "#141426",
      color: "#e6f0ff"
    }).then((r) => {
      if (r.isConfirmed) window.location.href = href;
    });
  });

  $(".preview-btn").on("click", function () {
    const name = $(this).data("name");
    Swal.fire({
      title: "File Preview",
      text: `Preview placeholder for: ${name}`,
      icon: "info",
      background: "#141426",
      color: "#e6f0ff"
    });
  });

  if (typeof Toastify !== "undefined") {
    $(".toast-flash").each(function () {
      Toastify({
        text: $(this).text(),
        gravity: "top",
        position: "right",
        style: { background: "linear-gradient(90deg,#00d4ff,#8c52ff)" }
      }).showToast();
      $(this).hide();
    });
  }

  const pass = document.getElementById("regPassword");
  const bar = document.getElementById("passwordStrengthBar");
  const txt = document.getElementById("passwordStrengthText");
  if (pass && bar && txt) {
    pass.addEventListener("input", function () {
      const v = pass.value;
      let score = 0;
      if (v.length >= 8) score++;
      if (/[A-Z]/.test(v)) score++;
      if (/[0-9]/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v)) score++;
      const pct = score * 25;
      bar.style.width = `${pct}%`;
      bar.style.background = pct < 50 ? "#ff6666" : pct < 75 ? "#ffc857" : "#00d4ff";
      txt.textContent = `Strength: ${pct < 50 ? "Weak" : pct < 75 ? "Medium" : "Strong"}`;
    });
  }

  const dropZone = document.getElementById("dropZone");
  const uploadInput = document.getElementById("uploadInput");
  const previewText = document.getElementById("previewText");
  if (dropZone && uploadInput) {
    ["dragenter", "dragover"].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add("drag-over"); }));
    ["dragleave", "drop"].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove("drag-over"); }));
    dropZone.addEventListener("drop", (e) => {
      if (!e.dataTransfer.files.length) return;
      uploadInput.files = e.dataTransfer.files;
      if (previewText) previewText.textContent = `${e.dataTransfer.files[0].name} (${Math.round(e.dataTransfer.files[0].size / 1024)} KB)`;
    });
    uploadInput.addEventListener("change", () => {
      if (uploadInput.files.length && previewText) {
        previewText.textContent = `${uploadInput.files[0].name} (${Math.round(uploadInput.files[0].size / 1024)} KB)`;
      }
    });
  }

  // Enable Bootstrap tooltips for icon buttons.
  if (window.bootstrap && bootstrap.Tooltip) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((el) => {
      // Avoid double-instantiation.
      if (!el._tooltip) {
        el._tooltip = new bootstrap.Tooltip(el);
      }
    });
  }

});
