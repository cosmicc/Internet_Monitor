"use strict";

(() => {
    const dashboard = document.getElementById("dashboard");
    if (!dashboard) {
        return;
    }

    const statusUrl = dashboard.dataset.statusUrl;
    const historyUrl = dashboard.dataset.historyUrl;
    const validHistoryRanges = new Set(["1h", "6h", "24h", "7d", "all"]);
    const historyRangeLabels = {
        "1h": "1 hour",
        "6h": "6 hours",
        "24h": "24 hours",
        "7d": "7 days",
        all: "container lifetime",
    };
    const historyAxisLabels = {
        "1h": "1 hour ago",
        "6h": "6 hours ago",
        "24h": "24 hours ago",
        "7d": "7 days ago",
        all: "Container start",
    };
    const historyRangeSeconds = {
        "1h": 60 * 60,
        "6h": 6 * 60 * 60,
        "24h": 24 * 60 * 60,
        "7d": 7 * 24 * 60 * 60,
    };
    const refreshMilliseconds = Math.max(
        1000,
        Number.parseInt(dashboard.dataset.refreshMs || "10000", 10),
    );
    const configuredDefaultRange = dashboard.dataset.historyDefaultRange;
    const defaultHistoryRange = validHistoryRanges.has(configuredDefaultRange)
        ? configuredDefaultRange
        : "24h";
    const statusClasses = [
        "status-up",
        "status-warning",
        "status-down",
        "status-unknown",
    ];
    const validStates = new Set(["up", "warning", "down", "unknown"]);
    const seriesByKey = new Map();
    const maximumSeriesPoints = 720;
    const svgNamespace = "http://www.w3.org/2000/svg";
    let activeHistoryRange = defaultHistoryRange;
    let chartStartTimestamp = null;
    let chartEndTimestamp = null;
    let historyStartedTimestamp = null;
    let historyRequestSequence = 0;
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

    function timestampToEpochSeconds(timestamp) {
        if (Number.isFinite(timestamp)) {
            return Number(timestamp);
        }
        const milliseconds = Date.parse(timestamp);
        return Number.isFinite(milliseconds) ? milliseconds / 1000 : null;
    }

    function appendSeriesPoint(
        key,
        timestamp,
        latencyMilliseconds,
        lossPercent,
        {draw = true} = {},
    ) {
        const epochSeconds = timestampToEpochSeconds(timestamp);
        const hasLatency = Number.isFinite(latencyMilliseconds);
        const hasLoss = Number.isFinite(lossPercent);
        if (!Number.isFinite(epochSeconds) || (!hasLatency && !hasLoss)) {
            return;
        }

        const sample = {
            timestamp: epochSeconds,
            latencyMilliseconds: hasLatency ? Number(latencyMilliseconds) : null,
            lossPercent: hasLoss
                ? Math.min(100, Math.max(0, Number(lossPercent)))
                : 0,
        };
        const samples = seriesByKey.get(key) || [];
        const latest = samples.at(-1);
        if (latest?.timestamp === sample.timestamp) {
            samples[samples.length - 1] = sample;
        } else {
            samples.push(sample);
        }
        if (samples.length > maximumSeriesPoints) {
            samples.splice(0, samples.length - maximumSeriesPoints);
        }
        seriesByKey.set(key, samples);
        if (draw) {
            drawSeries(key);
        }
    }

    function createSvgElement(tagName, className, attributes) {
        const element = document.createElementNS(svgNamespace, tagName);
        element.setAttribute("class", className);
        Object.entries(attributes).forEach(([name, value]) => {
            element.setAttribute(name, String(value));
        });
        return element;
    }

    function updateChartDescription(svg, samples) {
        const chartLabel = svg.dataset.chartLabel || "Latency";
        const isDnsChart = svg.dataset.chartKind === "dns";
        const failureSampleCount = samples.filter(
            (sample) => sample.lossPercent > 0,
        ).length;
        const latest = samples.at(-1);
        let latestDescription = "Latest sample unavailable.";

        if (latest) {
            if (latest.lossPercent >= 100 || latest.latencyMilliseconds === null) {
                latestDescription = isDnsChart
                    ? "The latest DNS check failed."
                    : `Latest sample has ${latest.lossPercent}% packet loss and no latency response.`;
            } else {
                latestDescription = isDnsChart
                    ? `Latest response time is ${latest.latencyMilliseconds.toFixed(2)} milliseconds.`
                    : `Latest sample is ${latest.latencyMilliseconds.toFixed(2)} milliseconds with ${latest.lossPercent}% packet loss.`;
            }
        }

        const failureDescription = failureSampleCount === 0
            ? (isDnsChart ? "No failed DNS checks are shown." : "No packet loss samples are shown.")
            : `${failureSampleCount} of ${samples.length} samples show ${isDnsChart ? "a failed DNS check" : "packet loss"} in red.`;
        svg.setAttribute(
            "aria-label",
            `${chartLabel} over retained container history. ${latestDescription} ${failureDescription}`,
        );
    }

    function drawSeries(key) {
        const samples = seriesByKey.get(key) || [];
        dashboard.querySelectorAll(`[data-sparkline="${key}"]`).forEach((svg) => {
            const latencyLayer = svg.querySelector("[data-series]");
            const lossLayer = svg.querySelector("[data-loss-series]");
            if (!latencyLayer || !lossLayer) {
                return;
            }
            latencyLayer.replaceChildren();
            lossLayer.replaceChildren();
            updateChartDescription(svg, samples);
            if (samples.length === 0) {
                return;
            }

            const viewBox = svg.viewBox.baseVal;
            const width = viewBox.width || 100;
            const height = viewBox.height || 28;
            const horizontalPadding = width > 100 ? 4 : 1;
            const verticalPadding = height > 50 ? 12 : 3;
            const finiteLatencies = samples
                .map((sample) => sample.latencyMilliseconds)
                .filter(Number.isFinite);
            const maximum = Math.max(...finiteLatencies, 1);
            const latencyRange = maximum * 1.15;
            const minimumTimestamp = Number.isFinite(chartStartTimestamp)
                ? chartStartTimestamp
                : samples[0].timestamp;
            const maximumTimestamp = Number.isFinite(chartEndTimestamp)
                ? chartEndTimestamp
                : samples.at(-1).timestamp;
            const timestampRange = Math.max(maximumTimestamp - minimumTimestamp, 1);
            const coordinates = samples.map((sample) => {
                const x = samples.length === 1
                    ? width - horizontalPadding
                    : horizontalPadding + (
                        (sample.timestamp - minimumTimestamp)
                        * (width - horizontalPadding * 2)
                    ) / timestampRange;
                if (!Number.isFinite(sample.latencyMilliseconds)) {
                    return {x, y: null};
                }
                const normalized = sample.latencyMilliseconds / latencyRange;
                const y = height - verticalPadding - normalized * (
                    height - verticalPadding * 2
                );
                return {x, y};
            });

            for (let index = 1; index < samples.length; index += 1) {
                const previousCoordinate = coordinates[index - 1];
                const coordinate = coordinates[index];
                if (previousCoordinate.y === null || coordinate.y === null) {
                    continue;
                }
                const hasFailure = (
                    samples[index - 1].lossPercent > 0
                    || samples[index].lossPercent > 0
                );
                latencyLayer.append(createSvgElement(
                    "line",
                    `chart-segment ${hasFailure ? "chart-segment-loss" : "chart-segment-clean"}`,
                    {
                        x1: previousCoordinate.x.toFixed(2),
                        y1: previousCoordinate.y.toFixed(2),
                        x2: coordinate.x.toFixed(2),
                        y2: coordinate.y.toFixed(2),
                    },
                ));
            }

            if (
                samples.length === 1
                && coordinates[0].y !== null
                && samples[0].lossPercent === 0
            ) {
                latencyLayer.append(createSvgElement(
                    "circle",
                    "chart-point chart-point-clean",
                    {
                        cx: coordinates[0].x.toFixed(2),
                        cy: coordinates[0].y.toFixed(2),
                        r: width > 100 ? 3 : 1.6,
                    },
                ));
            }

            samples.forEach((sample, index) => {
                if (sample.lossPercent <= 0) {
                    return;
                }
                const coordinate = coordinates[index];
                const isTotalFailure = (
                    sample.lossPercent >= 100
                    || coordinate.y === null
                );
                if (isTotalFailure) {
                    lossLayer.append(createSvgElement(
                        "line",
                        "chart-loss-outage",
                        {
                            x1: coordinate.x.toFixed(2),
                            y1: verticalPadding,
                            x2: coordinate.x.toFixed(2),
                            y2: height - verticalPadding,
                        },
                    ));
                    return;
                }

                lossLayer.append(createSvgElement(
                    "circle",
                    "chart-loss-point",
                    {
                        cx: coordinate.x.toFixed(2),
                        cy: coordinate.y.toFixed(2),
                        r: width > 100 ? 3.5 : 1.8,
                    },
                ));
            });
        });
    }

    function drawAllSeries() {
        const keys = new Set(
            [...dashboard.querySelectorAll("[data-sparkline]")].map(
                (svg) => svg.dataset.sparkline,
            ),
        );
        keys.forEach(drawSeries);
    }

    function setHistoryRangeState(rangeName) {
        activeHistoryRange = rangeName;
        dashboard.querySelectorAll("[data-history-range]").forEach((button) => {
            button.setAttribute(
                "aria-pressed",
                String(button.dataset.historyRange === rangeName),
            );
        });
        setText(
            "[data-history-caption]",
            `Container history · ${historyRangeLabels[rangeName]}`,
        );
        setText("[data-history-axis-start]", historyAxisLabels[rangeName]);
    }

    function historyResolutionLabel(resolution) {
        const labels = {
            detailed: "detailed samples",
            minute: "minute summaries",
            tiered: "tiered summaries",
        };
        return labels[resolution] || "retained samples";
    }

    function updateChartWindow(rangeName, endTimestamp) {
        if (!Number.isFinite(endTimestamp)) {
            chartStartTimestamp = null;
            chartEndTimestamp = null;
            return;
        }
        chartEndTimestamp = endTimestamp;
        if (rangeName === "all") {
            chartStartTimestamp = Number.isFinite(historyStartedTimestamp)
                ? historyStartedTimestamp
                : endTimestamp;
            setText("[data-history-axis-start]", "Container start");
            return;
        }

        const cutoff = endTimestamp - historyRangeSeconds[rangeName];
        const startsWithContainer = (
            Number.isFinite(historyStartedTimestamp)
            && historyStartedTimestamp > cutoff
        );
        chartStartTimestamp = startsWithContainer
            ? historyStartedTimestamp
            : cutoff;
        setText(
            "[data-history-axis-start]",
            startsWithContainer ? "Container start" : historyAxisLabels[rangeName],
        );
    }

    function renderHistory(payload) {
        seriesByKey.clear();
        const metadata = Array.isArray(payload?.series) ? payload.series : [];
        const points = Array.isArray(payload?.points) ? payload.points : [];
        historyStartedTimestamp = timestampToEpochSeconds(payload?.started_at);
        const updatedTimestamp = timestampToEpochSeconds(payload?.updated_at);
        updateChartWindow(activeHistoryRange, updatedTimestamp);
        metadata.forEach((series) => seriesByKey.set(series.id, []));
        points.forEach((point) => {
            if (!Array.isArray(point) || !Array.isArray(point[1])) {
                return;
            }
            const timestamp = point[0];
            metadata.forEach((series, index) => {
                const metric = point[1][index];
                if (!Array.isArray(metric)) {
                    return;
                }
                appendSeriesPoint(
                    series.id,
                    timestamp,
                    metric[0],
                    metric[1],
                    {draw: false},
                );
            });
        });
        drawAllSeries();

        if (payload?.updated_at) {
            lastRecordedTimestamp = payload.updated_at;
        }
        const sampleCount = Number.isFinite(payload?.point_count)
            ? Number(payload.point_count)
            : points.length;
        if (!payload?.available || sampleCount === 0) {
            setText(
                "[data-history-summary]",
                "No retained samples yet. History starts with the first completed check.",
            );
            return;
        }
        setText(
            "[data-history-summary]",
            `${sampleCount} ${sampleCount === 1 ? "sample" : "samples"} shown as ${historyResolutionLabel(payload.resolution)}. History resets when this container restarts.`,
        );
    }

    async function loadHistory(rangeName) {
        if (!validHistoryRanges.has(rangeName)) {
            return;
        }
        const requestSequence = ++historyRequestSequence;
        setHistoryRangeState(rangeName);
        setText("[data-history-summary]", "Loading retained history…");
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 7000);
        try {
            const url = new URL(historyUrl, window.location.href);
            url.searchParams.set("range", rangeName);
            const response = await fetch(url, {
                cache: "no-store",
                credentials: "same-origin",
                headers: {Accept: "application/json"},
                signal: controller.signal,
            });
            if (!response.ok) {
                throw new Error(`History endpoint returned HTTP ${response.status}`);
            }
            const payload = await response.json();
            if (requestSequence === historyRequestSequence) {
                renderHistory(payload);
            }
        } catch (_error) {
            if (requestSequence === historyRequestSequence) {
                setText(
                    "[data-history-summary]",
                    "Retained history is temporarily unavailable; live status will continue updating.",
                );
            }
        } finally {
            window.clearTimeout(timeout);
        }
    }

    function updatePath(nodes, recordPoint, timestamp) {
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
                appendSeriesPoint(
                    node.id,
                    timestamp,
                    node.average_latency_ms,
                    node.loss_percent,
                );
            }
        });
    }

    function updateInternet(internet, monitor, recordPoint, timestamp) {
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
            if (recordPoint) {
                appendSeriesPoint(
                    `internet-target-${index}`,
                    timestamp,
                    target.average_latency_ms,
                    target.loss_percent,
                );
            }
        });

        setText("[data-bind=\"active-target\"]", internet.host || "Unavailable");
        setText("[data-bind=\"target-selection\"]", internet.used_backup ? "Backup" : "Primary");
        setText("[data-bind=\"loop-duration\"]", formatMilliseconds(monitor.loop_duration_ms));
        setText("[data-bind=\"active-average\"]", formatMilliseconds(internet.average_latency_ms));
        if (recordPoint) {
            appendSeriesPoint(
                "internet",
                timestamp,
                internet.average_latency_ms,
                internet.loss_percent,
            );
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

    function dnsFailurePercent(result) {
        return normalizedStatus(result?.status).state === "down" ? 100 : 0;
    }

    function updateDns(dns, recordPoint, timestamp) {
        const panel = dashboard.querySelector(".dns-panel");
        updateBadge(panel?.querySelector(":scope > .section-heading [data-status-badge]"), dns.status);
        updateDnsRow(dashboard.querySelector("[data-resolver-row]"), dns.resolver);
        if (recordPoint) {
            appendSeriesPoint(
                "dns-resolver",
                timestamp,
                dns.resolver?.response_time_ms,
                dnsFailurePercent(dns.resolver),
            );
        }
        (dns.servers || []).forEach((server, index) => {
            const row = dashboard.querySelector(`[data-dns-index="${index}"]`);
            if (!row) {
                return;
            }
            setText("[data-dns-host]", server.server || "Unavailable", row);
            updateDnsRow(row, server);
            if (recordPoint) {
                appendSeriesPoint(
                    `dns-server-${index}`,
                    timestamp,
                    server.response_time_ms,
                    dnsFailurePercent(server),
                );
            }
        });
        setText("[data-bind=\"dns-host\"]", dns.hostname || "Unavailable");
        setText("[data-bind=\"dns-record-type\"]", dns.record_type || "Unavailable");
        setText("[data-bind=\"dns-threshold\"]", formatMilliseconds(dns.slow_threshold_ms));
        setText(
            "[data-bind=\"query-summary\"]",
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
            updateChartWindow(
                activeHistoryRange,
                timestampToEpochSeconds(status.last_updated),
            );
        }

        updateDiagnosis(status.diagnosis || {});
        updatePath(status.path_nodes || [], recordPoint, status.last_updated);
        updateInternet(
            status.internet || {},
            status.monitor || {},
            recordPoint,
            status.last_updated,
        );
        updateGateways(status.gateways || []);
        updateDns(status.dns || {}, recordPoint, status.last_updated);

        setText("[data-bind=\"last-updated\"]", formatDuration(status.snapshot_age_seconds));
        setText(
            "[data-bind=\"monitor-interval\"]",
            formatInterval(status.monitor?.interval_seconds),
        );
        setText("[data-bind=\"snapshot-age\"]", formatDuration(status.snapshot_age_seconds));
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

    dashboard.querySelectorAll("[data-history-range]").forEach((button) => {
        button.addEventListener("click", () => loadHistory(button.dataset.historyRange));
    });
    loadHistory(defaultHistoryRange).finally(pollStatus);
})();
