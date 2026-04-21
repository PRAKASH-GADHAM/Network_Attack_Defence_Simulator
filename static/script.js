'use strict';

// ═══════════════════════════════
// STATE
// ═══════════════════════════════
var _running = true;

// Chart instances — created once, updated incrementally
var barChart = null;
var lineChart = null;

// Locally accumulated attack type counts (bar chart)
var attackCounts = { dos: 0, port: 0, ml: 0, payload: 0 };

// Cursor for incremental /stats polling
var statsCursor = 0;
var consecutiveEmpty = 0;

// Dedup tracker for traffic buckets already plotted
var addedBuckets = {};

// ═══════════════════════════════
// ADAPTIVE POLLING
// ═══════════════════════════════
var MIN_POLL_MS = 1000;
var MAX_POLL_MS = 10000;
var pollIntervalMs = 2000;

function adaptPollInterval(hasActivity) {
    try {
        if (hasActivity) {
            pollIntervalMs = Math.max(MIN_POLL_MS, Math.floor(pollIntervalMs / 1.5));
            consecutiveEmpty = 0;
        } else {
            consecutiveEmpty++;
            if (consecutiveEmpty >= 3) {
                pollIntervalMs = Math.min(MAX_POLL_MS, pollIntervalMs + 1000);
            }
        }
    } catch (e) {
        console.error('[NADS] adaptPollInterval:', e);
    }
}

// ═══════════════════════════════
// CLOCK
// ═══════════════════════════════
function updateClock() {
    try {
        var el = document.getElementById('clock');
        if (el) el.textContent = new Date().toLocaleTimeString();
    } catch (e) {
        // silent — clock is non-critical
    }
}

// ═══════════════════════════════
// SAFE SET TEXT
// ═══════════════════════════════
function safeSetText(id, val) {
    try {
        if (val === undefined || val === null) return;
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    } catch (e) {
        // silent
    }
}

// ═══════════════════════════════
// SAFE FETCH — returns null on any failure
// ═══════════════════════════════
function safeFetch(url) {
    try {
        return fetch(url)
            .then(function (res) {
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return res.json();
            })
            .catch(function (err) {
                console.warn('[NADS] fetch(' + url + '):', err.message || err);
                return null;
            });
    } catch (e) {
        console.error('[NADS] safeFetch setup error:', e);
        return Promise.resolve(null);
    }
}

// ═══════════════════════════════
// ALERT TYPE DETECTION
// ═══════════════════════════════
function detectAlertType(text) {
    try {
        var t = (text || '').toLowerCase();
        if (t.indexOf('blocked') !== -1) return 'blocked';
        if (t.indexOf('dos') !== -1 || t.indexOf('flood') !== -1) return 'dos';
        if (t.indexOf('port scan') !== -1 || t.indexOf('port') !== -1) return 'port';
        if (t.indexOf('ml') !== -1 || t.indexOf('anomaly') !== -1) return 'ml';
        if (t.indexOf('payload') !== -1 || t.indexOf('suspicious') !== -1) return 'payload';
        return 'normal';
    } catch (e) {
        return 'normal';
    }
}

// ═══════════════════════════════
// DEMO BADGE
// ═══════════════════════════════
function updateDemoBadge(isActive) {
    try {
        var el = document.getElementById('demo-badge');
        if (!el) return;
        if (isActive) {
            el.textContent = 'DEMO ACTIVE';
            el.className = 'badge badge-orange animate-pulse';
            el.style.display = 'inline-flex';
        } else {
            el.style.display = 'none';
        }
    } catch (e) {
        // silent
    }
}

// ═══════════════════════════════
// LOAD DATA — Alerts + Logs
// ═══════════════════════════════
function loadData() {
    if (!_running) return Promise.resolve();

    return safeFetch('/data').then(function (data) {
        try {
            if (!data) return;

            updateDemoBadge(!!data.demo_mode);

            // ── Alerts list ──
            var alertEl = document.getElementById('alerts');
            if (alertEl && Array.isArray(data.alerts)) {
                try {
                    alertEl.innerHTML = '';
                    if (!data.alerts.length) {
                        var emptyLi = document.createElement('li');
                        emptyLi.className = 'alert-empty';
                        emptyLi.textContent = 'No alerts detected — monitoring active...';
                        alertEl.appendChild(emptyLi);
                    } else {
                        var reversed = data.alerts.slice().reverse();
                        for (var i = 0; i < reversed.length; i++) {
                            try {
                                var text = (reversed[i] || '').trim();
                                if (!text) continue;
                                var li = document.createElement('li');
                                li.textContent = text;
                                li.setAttribute('data-type', detectAlertType(text));
                                if (text.indexOf('[DEMO]') !== -1) li.style.opacity = '0.8';
                                alertEl.appendChild(li);
                            } catch (innerE) {
                                // skip this item
                            }
                        }
                    }
                } catch (alertBuildE) {
                    console.error('[NADS] alert list build error:', alertBuildE);
                }
            }

            // ── Log viewer ──
            var logsEl = document.getElementById('logs');
            if (logsEl && Array.isArray(data.logs)) {
                try {
                    logsEl.textContent = data.logs.join('');
                    logsEl.scrollTop = logsEl.scrollHeight;
                } catch (logE) {
                    // silent
                }
            }

        } catch (e) {
            console.error('[NADS] loadData handler:', e);
        }
    });
}

// ═══════════════════════════════
// CHART INIT — only if Chart.js + canvas both exist
// ═══════════════════════════════
function initCharts() {
    try {
        if (typeof Chart === 'undefined') {
            // Chart.js not loaded on this page — skip silently
            return;
        }

        // ── Bar chart ──
        var barEl = document.getElementById('barChart');
        if (barEl && !barChart) {
            try {
                barChart = new Chart(barEl, {
                    type: 'bar',
                    data: {
                        labels: ['DoS', 'Port Scan', 'ML Anomaly', 'Payload'],
                        datasets: [{
                            label: 'Attacks',
                            data: [0, 0, 0, 0],
                            backgroundColor: [
                                'rgba(248,  81,  73, 0.70)',
                                'rgba(219, 109,  40, 0.70)',
                                'rgba(188, 140, 255, 0.70)',
                                'rgba( 88, 166, 255, 0.70)'
                            ],
                            borderColor: [
                                'rgba(248,  81,  73, 1)',
                                'rgba(219, 109,  40, 1)',
                                'rgba(188, 140, 255, 1)',
                                'rgba( 88, 166, 255, 1)'
                            ],
                            borderWidth: 1,
                            borderRadius: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        animation: { duration: 250 },
                        plugins: { legend: { display: false } },
                        scales: {
                            x: {
                                grid: { color: 'rgba(48,54,61,0.5)' },
                                ticks: { color: '#8b949e', font: { size: 11 } }
                            },
                            y: {
                                beginAtZero: true,
                                grid: { color: 'rgba(48,54,61,0.5)' },
                                ticks: { color: '#8b949e', font: { size: 11 }, precision: 0 }
                            }
                        }
                    }
                });
            } catch (barE) {
                console.error('[NADS] barChart init failed:', barE);
                barChart = null;
            }
        }

        // ── Line chart ──
        var lineEl = document.getElementById('lineChart');
        if (lineEl && !lineChart) {
            try {
                lineChart = new Chart(lineEl, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Packets / sec',
                            data: [],
                            fill: true,
                            tension: 0.35,
                            borderColor: 'rgba(63, 185, 80, 1)',
                            backgroundColor: 'rgba(63, 185, 80, 0.08)',
                            pointRadius: 2,
                            pointHoverRadius: 4,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        animation: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: {
                                grid: { color: 'rgba(48,54,61,0.5)' },
                                ticks: { color: '#8b949e', font: { size: 11 }, maxTicksLimit: 8 }
                            },
                            y: {
                                beginAtZero: true,
                                grid: { color: 'rgba(48,54,61,0.5)' },
                                ticks: { color: '#8b949e', font: { size: 11 }, precision: 0 }
                            }
                        }
                    }
                });
            } catch (lineE) {
                console.error('[NADS] lineChart init failed:', lineE);
                lineChart = null;
            }
        }

    } catch (e) {
        console.error('[NADS] initCharts:', e);
    }
}

// ═══════════════════════════════
// UPDATE BAR CHART
// ═══════════════════════════════
function updateBarChart() {
    try {
        if (!barChart) return;
        barChart.data.datasets[0].data = [
            attackCounts.dos,
            attackCounts.port,
            attackCounts.ml,
            attackCounts.payload
        ];
        barChart.update('none');
    } catch (e) {
        console.error('[NADS] updateBarChart:', e);
    }
}

// ═══════════════════════════════
// LOAD STATS — cursor-based incremental
// ═══════════════════════════════
function loadStats() {
    try {
        var url = statsCursor > 0 ? ('/stats?since=' + statsCursor) : '/stats';

        return safeFetch(url).then(function (raw) {
            try {
                if (!raw) {
                    adaptPollInterval(false);
                    return;
                }

                var items, nextSince;

                if (Array.isArray(raw)) {
                    items = raw;
                    nextSince = items.length ? items[items.length - 1].time : statsCursor;
                } else {
                    items = raw.items || [];
                    nextSince = raw.next_since || statsCursor;
                }

                if (!items.length) {
                    adaptPollInterval(false);
                    return;
                }

                for (var i = 0; i < items.length; i++) {
                    try {
                        var t = items[i].type;
                        if (t && t in attackCounts) {
                            attackCounts[t]++;
                        }
                    } catch (itemE) {
                        // skip bad item
                    }
                }

                statsCursor = nextSince;
                adaptPollInterval(true);
                updateBarChart();

            } catch (e) {
                console.error('[NADS] loadStats handler:', e);
            }
        });
    } catch (e) {
        console.error('[NADS] loadStats setup:', e);
        return Promise.resolve();
    }
}

// ═══════════════════════════════
// LOAD TRAFFIC BUCKETS
// ═══════════════════════════════
function loadTrafficBuckets() {
    try {
        if (!lineChart) return Promise.resolve();

        return safeFetch('/traffic_buckets').then(function (buckets) {
            try {
                if (!lineChart) return; // re-check after async gap
                if (!buckets || !Array.isArray(buckets)) return;

                var MAX_POINTS = 60;
                var changed = false;

                for (var i = 0; i < buckets.length; i++) {
                    try {
                        var ts = buckets[i][0];
                        var count = buckets[i][1];
                        if (addedBuckets[ts]) continue;
                        addedBuckets[ts] = true;

                        var label = new Date(ts * 1000).toLocaleTimeString();
                        lineChart.data.labels.push(label);
                        lineChart.data.datasets[0].data.push(count);

                        if (lineChart.data.labels.length > MAX_POINTS) {
                            lineChart.data.labels.shift();
                            lineChart.data.datasets[0].data.shift();
                        }
                        changed = true;
                    } catch (bucketE) {
                        // skip bad bucket
                    }
                }

                if (changed) lineChart.update('none');

            } catch (e) {
                console.error('[NADS] loadTrafficBuckets handler:', e);
            }
        });
    } catch (e) {
        console.error('[NADS] loadTrafficBuckets setup:', e);
        return Promise.resolve();
    }
}

// ═══════════════════════════════
// LOAD TOP IPs
// ═══════════════════════════════
function loadTopIPs() {
    try {
        var el = document.getElementById('topIPs');
        if (!el) return Promise.resolve();

        return safeFetch('/top_ips').then(function (data) {
            try {
                var listEl = document.getElementById('topIPs'); // re-fetch in case DOM changed
                if (!listEl) return;

                if (!data || !Array.isArray(data)) {
                    return;
                }

                listEl.innerHTML = '';

                if (!data.length) {
                    var noDataLi = document.createElement('li');
                    noDataLi.className = 'text-muted text-sm';
                    noDataLi.textContent = 'No traffic data yet...';
                    listEl.appendChild(noDataLi);
                    return;
                }

                for (var i = 0; i < data.length; i++) {
                    try {
                        var ip = data[i][0];
                        var count = data[i][1];

                        var li = document.createElement('li');
                        var left = document.createElement('span');
                        left.className = 'top-ip-left';

                        var rank = document.createElement('span');
                        rank.className = 'top-ip-rank';
                        rank.textContent = '#' + (i + 1);

                        var addr = document.createElement('span');
                        addr.className = 'text-mono';
                        addr.textContent = ip;

                        left.appendChild(rank);
                        left.appendChild(addr);

                        var right = document.createElement('span');
                        right.className = 'badge badge-muted';
                        right.textContent = count + ' pkts';

                        li.appendChild(left);
                        li.appendChild(right);
                        listEl.appendChild(li);
                    } catch (rowE) {
                        // skip bad row
                    }
                }
            } catch (e) {
                console.error('[NADS] loadTopIPs handler:', e);
            }
        });
    } catch (e) {
        console.error('[NADS] loadTopIPs setup:', e);
        return Promise.resolve();
    }
}

// ═══════════════════════════════
// LOAD SUMMARY
// ═══════════════════════════════
function loadSummary() {
    try {
        return safeFetch('/summary').then(function (data) {
            try {
                if (!data) return;

                safeSetText('sum-dos', data.dos || 0);
                safeSetText('sum-port', data.port || 0);
                safeSetText('sum-ml', data.ml || 0);
                safeSetText('sum-payload', data.payload || 0);
                safeSetText('sum-blocked', data.blocked_ips || 0);
                safeSetText('sum-total', data.total || 0);

                safeSetText('stat-alerts', data.alert_count);
                safeSetText('stat-stats', data.total);
                safeSetText('stat-blocked', data.blocked_ips);
                safeSetText('stat-queue', data.queue_depth);

                updateDemoBadge(!!data.demo_mode);

                try {
                    var mlBadge = document.getElementById('ml-badge');
                    if (mlBadge && data.ml_trained) {
                        mlBadge.textContent = 'TRAINED';
                        mlBadge.className = 'badge badge-green';
                    }
                } catch (e) { /* silent */ }

            } catch (e) {
                console.error('[NADS] loadSummary handler:', e);
            }
        });
    } catch (e) {
        console.error('[NADS] loadSummary setup:', e);
        return Promise.resolve();
    }
}

// ═══════════════════════════════
// MATRIX RAIN EFFECT
// Isolated completely — failure here never affects data or UI
// ═══════════════════════════════
function matrixEffect() {
    try {
        var bg = document.querySelector('.matrix-bg');
        if (!bg) return;
        if (bg.querySelector('canvas')) return; // already initialized

        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        bg.appendChild(canvas);

        var fontSize = 14;
        var letters = '01';
        var drops = [];
        var _timer = null;

        function resize() {
            try {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
                // Rebuild drops array on resize to match new column count
                var cols = Math.max(1, Math.floor(canvas.width / fontSize));
                drops = [];
                for (var i = 0; i < cols; i++) drops.push(1);
            } catch (e) { /* silent */ }
        }

        resize();

        // Use a named handler so we can avoid adding it multiple times
        if (!window._nadsResizeAttached) {
            window.addEventListener('resize', function () {
                try { resize(); } catch (e) { /* silent */ }
            });
            window._nadsResizeAttached = true;
        }

        function draw() {
            try {
                ctx.fillStyle = 'rgba(0,0,0,0.05)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = '#0f0';
                ctx.font = fontSize + 'px monospace';
                for (var i = 0; i < drops.length; i++) {
                    var char = letters[Math.floor(Math.random() * letters.length)];
                    ctx.fillText(char, i * fontSize, drops[i] * fontSize);
                    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                        drops[i] = 0;
                    }
                    drops[i]++;
                }
            } catch (e) { /* silent — draw errors are non-critical */ }
        }

        _timer = setInterval(draw, 33);

    } catch (e) {
        console.error('[NADS] matrixEffect:', e);
    }
}

// ═══════════════════════════════
// SAFE PROMISE WRAPPER
// Ensures a function always returns a resolved promise
// ═══════════════════════════════
function safeCall(fn, label) {
    try {
        var result = fn();
        if (result && typeof result.then === 'function') {
            return result.catch(function (e) {
                console.error('[NADS] ' + (label || 'async') + ' error:', e);
            });
        }
        return Promise.resolve();
    } catch (e) {
        console.error('[NADS] ' + (label || 'call') + ' error:', e);
        return Promise.resolve();
    }
}

// ═══════════════════════════════
// POLLING LOOPS — self-scheduling, never stack-overflow
// ═══════════════════════════════
var _dataPollActive = false;
var _chartPollActive = false;

function scheduleDataPoll() {
    if (_dataPollActive) return;
    _dataPollActive = true;

    setTimeout(function () {
        _dataPollActive = false;
        try {
            Promise.all([
                safeCall(loadData, 'loadData'),
                safeCall(loadStats, 'loadStats')
            ]).catch(function () { }).finally(function () {
                scheduleDataPoll();
            });
        } catch (e) {
            console.error('[NADS] scheduleDataPoll tick:', e);
            scheduleDataPoll(); // always reschedule
        }
    }, pollIntervalMs);
}

function scheduleChartPoll() {
    if (_chartPollActive) return;
    _chartPollActive = true;

    setTimeout(function () {
        _chartPollActive = false;
        try {
            Promise.all([
                safeCall(loadTrafficBuckets, 'loadTrafficBuckets'),
                safeCall(loadTopIPs, 'loadTopIPs'),
                safeCall(loadSummary, 'loadSummary')
            ]).catch(function () { }).finally(function () {
                scheduleChartPoll();
            });
        } catch (e) {
            console.error('[NADS] scheduleChartPoll tick:', e);
            scheduleChartPoll(); // always reschedule
        }
    }, 4000);
}

// ═══════════════════════════════
// INIT — runs on DOMContentLoaded
// ═══════════════════════════════
function nadsInit() {
    try {
        // Charts must init first (depends on Chart.js being loaded above)
        safeCall(initCharts, 'initCharts');

        // Matrix background — fully isolated
        safeCall(matrixEffect, 'matrixEffect');

        // Initial data load
        safeCall(loadData, 'loadData-init');
        safeCall(loadStats, 'loadStats-init');
        safeCall(loadTrafficBuckets, 'loadTrafficBuckets-init');
        safeCall(loadTopIPs, 'loadTopIPs-init');
        safeCall(loadSummary, 'loadSummary-init');

        // Start polling loops
        scheduleDataPoll();
        scheduleChartPoll();

        // Clock
        updateClock();
        setInterval(updateClock, 1000);

    } catch (e) {
        console.error('[NADS] nadsInit fatal:', e);
        // Even if init fails, page HTML is already rendered — no blank screen
    }
}

// ── Entry point ──
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', nadsInit);
} else {
    // DOMContentLoaded already fired (script is deferred or at bottom of body)
    nadsInit();
}