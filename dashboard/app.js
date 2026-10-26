/* =====================================================================
   SOC CYBERSHIELD - Dashboard Frontend Application Logic
   Communicates with FastAPI backend endpoints:
   - /stats/overview
   - /alerts/recent
   - /analytics/attack-distribution
   - /analytics/top-talkers
   ===================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // Chart instances
  let attackDistChart = null;
  let timelineChart = null;
  let topPortsChart = null;

  // Auto refresh state
  let autoRefreshEnabled = true;
  let refreshIntervalId = null;
  const REFRESH_INTERVAL_MS = 3000;

  // Attack category colors mapping
  const ATTACK_COLORS = {
    DDoS: "#ef4444",
    PortScan: "#f97316",
    WebAttack: "#a855f7",
    Botnet: "#06b6d4",
    Other: "#64748b",
    Benign: "#10b981"
  };

  function getBadgeClass(type) {
    const t = (type || "").toLowerCase();
    if (t.includes("ddos")) return "badge-ddos";
    if (t.includes("portscan") || t.includes("scan")) return "badge-portscan";
    if (t.includes("web")) return "badge-webattack";
    if (t.includes("bot")) return "badge-botnet";
    return "badge-other";
  }

  // --- Initializing Charts ---
  function initCharts() {
    // 1. Attack Distribution Donut
    const ctxDist = document.getElementById("chart-attack-distribution").getContext("2d");
    attackDistChart = new Chart(ctxDist, {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: [],
          borderColor: "#0a0d14",
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              boxWidth: 12,
              color: "#94a3b8",
              font: { family: "'Outfit', sans-serif", size: 11 }
            }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${ctx.raw} cuộc (${ctx.dataset.percentages ? ctx.dataset.percentages[ctx.dataIndex] : ''}%)`
            }
          }
        },
        cutout: "68%"
      }
    });

    // 2. Timeline Line Chart
    const ctxTime = document.getElementById("chart-timeline").getContext("2d");
    timelineChart = new Chart(ctxTime, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "Số sự kiện tấn công phát hiện",
          data: [],
          borderColor: "#00e5ff",
          backgroundColor: "rgba(0, 229, 255, 0.08)",
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointHoverRadius: 6,
          pointBackgroundColor: "#00e5ff"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#64748b", font: { size: 10 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#64748b", font: { size: 10 } }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });

    // 3. Top Ports Bar Chart
    const ctxPorts = document.getElementById("chart-top-ports").getContext("2d");
    topPortsChart = new Chart(ctxPorts, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: "rgba(168, 85, 247, 0.4)",
          borderColor: "#a855f7",
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: "#64748b", font: { size: 9 } }
          },
          y: {
            grid: { display: false },
            ticks: { color: "#94a3b8", font: { size: 10, family: "'JetBrains Mono', monospace" } }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  // --- API Fetchers ---
  async function fetchOverview() {
    try {
      const res = await fetch("/stats/overview");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      document.getElementById("kpi-total-flows").textContent = data.total_flows.toLocaleString();
      document.getElementById("kpi-total-alerts").textContent = data.total_alerts.toLocaleString();
      document.getElementById("kpi-attack-ratio").textContent = `${data.attack_ratio_pct}%`;
      
      const p50 = data.streaming.latency_p50_ms;
      const p95 = data.streaming.latency_p95_ms;
      document.getElementById("kpi-latency").innerHTML = `${p50} / ${p95} <span class="unit">ms</span>`;
      document.getElementById("kpi-batch-info").textContent = `${data.streaming.recent_batches_evaluated} lô micro-batch (${data.streaming.total_rows_loaded.toLocaleString()} dòng)`;
    } catch (err) {
      console.warn("fetchOverview error:", err);
    }
  }

  async function fetchAttackDistribution() {
    try {
      const res = await fetch("/analytics/attack-distribution");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (attackDistChart && data.distribution && data.distribution.length > 0) {
        const labels = data.distribution.map(d => d.attack_type);
        const counts = data.distribution.map(d => d.count);
        const pcts = data.distribution.map(d => d.percentage);
        const colors = labels.map(l => ATTACK_COLORS[l] || "#94a3b8");

        attackDistChart.data.labels = labels;
        attackDistChart.data.datasets[0].data = counts;
        attackDistChart.data.datasets[0].backgroundColor = colors;
        attackDistChart.data.datasets[0].percentages = pcts;
        attackDistChart.update();
      }

      if (timelineChart && data.timeline && data.timeline.length > 0) {
        // Group counts by time bucket
        const timeMap = {};
        data.timeline.forEach(t => {
          const formatted = new Date(t.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          timeMap[formatted] = (timeMap[formatted] || 0) + t.count;
        });

        timelineChart.data.labels = Object.keys(timeMap);
        timelineChart.data.datasets[0].data = Object.values(timeMap);
        timelineChart.update();
      }
    } catch (err) {
      console.warn("fetchAttackDistribution error:", err);
    }
  }

  async function fetchRecentAlerts() {
    try {
      const filterSelect = document.getElementById("filter-attack-type");
      const attackType = filterSelect.value;
      const url = `/alerts/recent?limit=50${attackType ? '&attack_type=' + encodeURIComponent(attackType) : ''}`;
      
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const tbody = document.getElementById("tbody-alerts");
      if (!data.alerts || data.alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="loading-td">Chưa có cảnh báo tấn công nào ghi nhận.</td></tr>`;
        return;
      }

      tbody.innerHTML = data.alerts.map(a => {
        const logId = a.source_log_id || `#${a.alert_id}`;
        const ts = a.flow_start_ts ? new Date(a.flow_start_ts).toLocaleString() : '--';
        const badgeCls = getBadgeClass(a.attack_type);

        return `
          <tr>
            <td><strong>${logId}</strong></td>
            <td>${ts}</td>
            <td class="highlight-blue">${a.src_ip}</td>
            <td>${a.dst_ip}</td>
            <td><span class="unit">Port</span> ${a.dst_port}</td>
            <td><span class="badge ${badgeCls}">${a.attack_type}</span></td>
            <td><span class="status-intercepted">Đã ngăn chặn</span></td>
          </tr>
        `;
      }).join("");

    } catch (err) {
      console.warn("fetchRecentAlerts error:", err);
    }
  }

  async function fetchTopTalkers() {
    try {
      const res = await fetch("/analytics/top-talkers?limit=8");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      // 1. Top Attackers Table
      const tbody = document.getElementById("tbody-top-attackers");
      if (!data.top_attackers || data.top_attackers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="loading-td">Chưa có dữ liệu kẻ tấn công.</td></tr>`;
      } else {
        tbody.innerHTML = data.top_attackers.map(att => {
          const blBadge = att.is_blacklisted 
            ? `<span class="badge badge-blacklisted" title="${att.blacklist_source}">BLACKLIST</span>` 
            : `<span class="badge badge-clean">CLEAR</span>`;
          const types = (att.attack_types || []).join(", ");
          return `
            <tr>
              <td class="highlight-blue">${att.ip}</td>
              <td><strong>${att.attack_count}</strong></td>
              <td><span class="unit">${types}</span></td>
              <td>${blBadge}</td>
            </tr>
          `;
        }).join("");
      }

      // 2. Top Targeted Ports Bar Chart
      if (topPortsChart && data.top_targeted_ports && data.top_targeted_ports.length > 0) {
        const labels = data.top_targeted_ports.map(p => `${p.port} (${p.service_name})`);
        const counts = data.top_targeted_ports.map(p => p.attack_count);

        topPortsChart.data.labels = labels;
        topPortsChart.data.datasets[0].data = counts;
        topPortsChart.update();
      }

    } catch (err) {
      console.warn("fetchTopTalkers error:", err);
    }
  }

  // --- Master Refresh Routine ---
  async function refreshDashboard() {
    await Promise.allSettled([
      fetchOverview(),
      fetchAttackDistribution(),
      fetchRecentAlerts(),
      fetchTopTalkers()
    ]);
  }

  // --- Control Handlers ---
  document.getElementById("btn-refresh").addEventListener("click", () => {
    refreshDashboard();
  });

  document.getElementById("filter-attack-type").addEventListener("change", () => {
    fetchRecentAlerts();
  });

  const btnToggleAuto = document.getElementById("btn-toggle-auto");
  const autoBtnIcon = document.getElementById("auto-btn-icon");
  const autoBtnLabel = document.getElementById("auto-btn-label");
  const liveStatusText = document.getElementById("live-status-text");

  btnToggleAuto.addEventListener("click", () => {
    autoRefreshEnabled = !autoRefreshEnabled;
    if (autoRefreshEnabled) {
      autoBtnIcon.textContent = "⏸";
      autoBtnLabel.textContent = "Tự động (3s)";
      liveStatusText.textContent = "LIVE STREAMING";
      startAutoRefresh();
    } else {
      autoBtnIcon.textContent = "▶";
      autoBtnLabel.textContent = "Đã tạm dừng";
      liveStatusText.textContent = "PAUSED";
      stopAutoRefresh();
    }
  });

  function startAutoRefresh() {
    if (refreshIntervalId) clearInterval(refreshIntervalId);
    refreshIntervalId = setInterval(refreshDashboard, REFRESH_INTERVAL_MS);
  }

  function stopAutoRefresh() {
    if (refreshIntervalId) clearInterval(refreshIntervalId);
    refreshIntervalId = null;
  }

  // Initialize and kick off
  initCharts();
  refreshDashboard();
  startAutoRefresh();
});
