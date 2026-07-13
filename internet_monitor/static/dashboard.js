"use strict";

(() => {
    const dashboard = document.getElementById("dashboard");
    if (!dashboard) {
        return;
    }

    const statusUrl = dashboard.dataset.statusUrl;
    const refreshMilliseconds = Math.max(
        1000,
        Number.parseInt(dashboard.dataset.refreshMs || "10000", 10),
    );
    const statusClasses = [
        "status-up",
        "status-warning",
        "status-down",
        "status-unknown",
    ];
    const validStates = new Set(["up", "warning", "down", "unknown"]);
    const seriesByKey = new Map();
    const maximumSeriesPoints = 120;
    let lastRecordedTimestamp = "";

    function normalizedStatus(status) {
        const state = validStates.has(status?.state) ? status.state : "unknown";
        const labels = {
            up: "Up",
            warning: "Degraded",
            down: "Down",
            unknown: "Unknown",
        };
        return {state, text: status?.text || labels[state]};
    }

    function applyStatusClass(element, status) {
        if (!element) {
            return;
        }
        const normalized = normalizedStatus(status);
        element.classList.remove(...statusClasses);
        element.classList.add(`status-${normalized.state}`);
        element.dataset.state = normalized.state;
    }

    function updateBadge(element, status) {
        if (!element) {
            return;
        }
        const normalized = normalizedStatus(status);
        applyStatusClass(element, normalized);
        const text = element.querySelector("[data-status-text]");
        if (text) {
            text.textContent = normalized.text;
        }
    }

    function setText(selector, value, scope = dashboard) {
        const element = scope.querySelector(selector);
        if (element) {
            element.textContent = value;
        }
    }

    function formatMilliseconds(value) {
        return Number.isFinite(value) ? `${Number(value).toFixed(2)} ms` : "Unavailable";
    }

    function formatPercent(value) {
        return Number.isFinite(value) ? `${Number(value)}%` : "Unavailable";
    }

    function formatPackets(transmitted, received) {
        return Number.isFinite(transmitted) && Number.isFinite(received)
            ? `${Number(transmitted)} / ${Number(received)}`
            : "Unavailable";
    }

    function formatLatencyRange(target) {
        const values = [
            target?.minimum_latency_ms,
            target?.average_latency_ms,
            target?.maximum_latency_ms,
        ];
        if (!values.every(Number.isFinite)) {
            return "Unavailable";
        }
        return `${values.map((value) => Number(value).toFixed(2)).join(" / ")} ms`;
    }

    function formatDuration(seconds) {
        if (!Number.isFinite(seconds)) {
            return "Unavailable";
        }
        if (seconds < 5) {
            return "just now";
        }
        if (seconds < 60) {
            return `${Math.round(seconds)} seconds ago`;
        }
        const minutes = Math.round(seconds / 60);
        return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
    }

    function formatInterval(seconds) {
        if (!Number.isFinite(seconds)) {
            return "Unavailable";
        }
        return `${Number(seconds)} second${Number(seconds) === 1 ? "" : "s"}`;
    }

    function addSeriesPoint(key, value) {
        if (!Number.isFinite(value)) {
            return;
        }
        const values = seriesByKey.get(key) || [];
        values.push(Number(value));
        if (values.length > maximumSeriesPoints) {
            values.splice(0, values.length - maximumSeriesPoints);
        }
        seriesByKey.set(key, values);
        drawSeries(key);
    }

    function drawSeries(key) {
        const values = seriesByKey.get(key) || [];
        dashboard.querySelectorAll(`[data-sparkline="${key}"]`).forEach((svg) => {
            const line = svg.querySelector("[data-series]");
            if (!line || values.length === 0) {
                return;
            }

            const viewBox = svg.viewBox.baseVal;
            const width = viewBox.width || 100;
            const height = viewBox.height || 28;
            const horizontalPadding = width > 100 ? 4 : 1;
            const verticalPadding = height > 50 ? 12 : 3;
            const minimum = 0;
            const maximum = Math.max(...values, 1);
            const range = maximum * 1.15;
            const points = values.length === 1 ? [values[0], values[0]] : values;
            const coordinates = points.map((value, index) => {
                const x = horizontalPadding + (
                    index * (width - horizontalPadding * 2)
                ) / Math.max(1, points.length - 1);
                const normalized = (value - minimum) / range;
                const y = height - verticalPadding - normalized * (
                    height - verticalPadding * 2
                );
                return `${x.toFixed(2)},${y.toFixed(2)}`;
            });
            line.setAttribute("points", coordinates.join(" "));
        });
    }

    function updatePath(nodes, recordPoint) {
        const nodeElements = new Map(
            [...dashboard.querySelectorAll("[data-path-node]")].map((element) => [
                element.dataset.pathNode,
                element,
            ]),
        );
        (nodes || []).forEach((node) => {
            const element = nodeElements.get(node.id);
            if (!element) {
                return;
            }
            applyStatusClass(element, node.status);
            updateBadge(element.querySelector("[data-status-badge]"), node.status);
            if (node.id === "server") {
                return;
            }
            setText(
                "[data-node-host]",
                node.configured === false ? "Not configured" : (node.host || "Unavailable"),
                element,
            );
            setText("[data-node-average]", formatMilliseconds(node.average_latency_ms), element);
            setText("[data-node-loss]", formatPercent(node.loss_percent), element);
            if (recordPoint && node.id !== "internet") {
                addSeriesPoint(node.id, node.average_latency_ms);
            }
        });
    }

    function updateInternet(internet, monitor, recordPoint) {
        const panel = dashboard.querySelector(".internet-panel");
        updateBadge(panel?.querySelector(":scope > .section-heading [data-status-badge]"), internet.status);

        (internet.targets || []).forEach((target, index) => {
            const row = dashboard.querySelector(`[data-target-index="${index}"]`);
            if (!row) {
                return;
            }
            setText("[data-target-role]", target.role || "Target", row);
            setText("[data-target-host]", target.host || "Unavailable", row);
            updateBadge(row.querySelector("[data-status-badge]"), target.status);
            setText("[data-target-latency]", formatLatencyRange(target), row);
            setText(
                "[data-target-packets]",
                formatPackets(target.transmitted, target.received),
                row,
            );
            setText("[data-target-loss]", formatPercent(target.loss_percent), row);
        });

        setText('[data-bind="active-target"]', internet.host || "Unavailable");
        setText('[data-bind="target-selection"]', internet.used_backup ? "Backup" : "Primary");
        setText('[data-bind="loop-duration"]', formatMilliseconds(monitor.loop_duration_ms));
        setText('[data-bind="active-average"]', formatMilliseconds(internet.average_latency_ms));
        if (recordPoint) {
            addSeriesPoint("internet", internet.average_latency_ms);
        }
    }

    function updateGateways(gateways) {
        (gateways || []).forEach((gateway, index) => {
            const detail = dashboard.querySelector(`[data-gateway-index="${index}"]`);
            if (!detail) {
                return;
            }
            applyStatusClass(detail, gateway.status);
            updateBadge(detail.querySelector("[data-status-badge]"), gateway.status);
            setText(
                "[data-gateway-host]",
                gateway.configured === false ? "Not configured" : (gateway.host || "Unavailable"),
                detail,
            );
            setText("[data-gateway-min]", formatMilliseconds(gateway.minimum_latency_ms), detail);
            setText("[data-gateway-average]", formatMilliseconds(gateway.average_latency_ms), detail);
            setText("[data-gateway-max]", formatMilliseconds(gateway.maximum_latency_ms), detail);
            setText("[data-gateway-loss]", formatPercent(gateway.loss_percent), detail);
            setText(
                "[data-gateway-packets]",
                formatPackets(gateway.transmitted, gateway.received),
                detail,
            );
        });
    }

    function updateDnsRow(row, result) {
        if (!row || !result) {
            return;
        }
        updateBadge(row.querySelector("[data-status-badge]"), result.status);
        setText("[data-dns-time]", formatMilliseconds(result.response_time_ms), row);
        setText("[data-dns-response]", result.response_status || "Unknown", row);
        setText(
            "[data-dns-answers]",
            Number.isFinite(result.answer_count) ? String(result.answer_count) : "—",
            row,
        );
    }

    function updateDns(dns) {
        const panel = dashboard.querySelector(".dns-panel");
        updateBadge(panel?.querySelector(":scope > .section-heading [data-status-badge]"), dns.status);
        updateDnsRow(dashboard.querySelector("[data-resolver-row]"), dns.resolver);
        (dns.servers || []).forEach((server, index) => {
            const row = dashboard.querySelector(`[data-dns-index="${index}"]`);
            if (!row) {
                return;
            }
            setText("[data-dns-host]", server.server || "Unavailable", row);
            updateDnsRow(row, server);
        });
        setText('[data-bind="dns-host"]', dns.hostname || "Unavailable");
        setText('[data-bind="dns-record-type"]', dns.record_type || "Unavailable");
        setText('[data-bind="dns-threshold"]', formatMilliseconds(dns.slow_threshold_ms));
        setText(
            '[data-bind="query-summary"]',
            `${dns.hostname || "Unavailable"} (${dns.record_type || "Unknown"})`,
        );
    }

    function updateDiagnosis(diagnosis) {
        const banner = dashboard.querySelector("[data-diagnosis]");
        applyStatusClass(banner, diagnosis.status);
        setText("[data-diagnosis-title]", diagnosis.title || "Status unavailable", banner);
        setText("[data-diagnosis-detail]", diagnosis.detail || "No diagnosis available.", banner);
        const icons = {up: "✓", warning: "!", down: "×", unknown: "?"};
        const state = normalizedStatus(diagnosis.status).state;
        setText("[data-diagnosis-icon]", icons[state], banner);
    }

    function renderStatus(status) {
        const recordPoint = Boolean(
            status.fresh
            && status.last_updated
            && status.last_updated !== lastRecordedTimestamp
        );
        if (recordPoint) {
            lastRecordedTimestamp = status.last_updated;
        }

        updateDiagnosis(status.diagnosis || {});
        updatePath(status.path_nodes || [], recordPoint);
        updateInternet(status.internet || {}, status.monitor || {}, recordPoint);
        updateGateways(status.gateways || []);
        updateDns(status.dns || {});

        setText('[data-bind="last-updated"]', formatDuration(status.snapshot_age_seconds));
        setText(
            '[data-bind="monitor-interval"]',
            formatInterval(status.monitor?.interval_seconds),
        );
        setText('[data-bind="snapshot-age"]', formatDuration(status.snapshot_age_seconds));
    }

    function setLiveState(success) {
        const indicator = dashboard.querySelector("[data-live-indicator]");
        const text = dashboard.querySelector("[data-live-text]");
        indicator?.classList.toggle("is-error", !success);
        if (text) {
            text.textContent = success ? "Live" : "Update delayed";
        }
    }

    async function pollStatus() {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 5000);
        try {
            const response = await fetch(statusUrl, {
                cache: "no-store",
                credentials: "same-origin",
                headers: {Accept: "application/json"},
                signal: controller.signal,
            });
            if (!response.ok) {
                throw new Error(`Status endpoint returned HTTP ${response.status}`);
            }
            renderStatus(await response.json());
            setLiveState(true);
        } catch (_error) {
            setLiveState(false);
        } finally {
            window.clearTimeout(timeout);
            window.setTimeout(pollStatus, refreshMilliseconds);
        }
    }

    pollStatus();
})();
