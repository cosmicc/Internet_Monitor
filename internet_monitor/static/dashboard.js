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
    const svgNamespace = "http://www.w3.org/2000/svg";
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

    function addSeriesPoint(key, latencyMilliseconds, lossPercent) {
        const hasLatency = Number.isFinite(latencyMilliseconds);
        const hasLoss = Number.isFinite(lossPercent);
        if (!hasLatency && !hasLoss) {
            return;
        }

        const samples = seriesByKey.get(key) || [];
        samples.push({
            latencyMilliseconds: hasLatency ? Number(latencyMilliseconds) : null,
            lossPercent: hasLoss
                ? Math.min(100, Math.max(0, Number(lossPercent)))
                : 0,
        });
        if (samples.length > maximumSeriesPoints) {
            samples.splice(0, samples.length - maximumSeriesPoints);
        }
        seriesByKey.set(key, samples);
        drawSeries(key);
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
        const lossSampleCount = samples.filter(
            (sample) => sample.lossPercent > 0,
        ).length;
        const latest = samples.at(-1);
        let latestDescription = "Latest sample unavailable.";

        if (latest) {
            if (latest.lossPercent >= 100 || latest.latencyMilliseconds === null) {
                latestDescription = `Latest sample has ${latest.lossPercent}% packet loss and no latency response.`;
            } else {
                latestDescription = `Latest sample is ${latest.latencyMilliseconds.toFixed(2)} milliseconds with ${latest.lossPercent}% packet loss.`;
            }
        }

        const lossDescription = lossSampleCount === 0
            ? "No packet loss samples are shown."
            : `${lossSampleCount} of ${samples.length} samples show packet loss in red.`;
        svg.setAttribute(
            "aria-label",
            `${chartLabel} during this browser session. ${latestDescription} ${lossDescription}`,
        );
    }

    function drawSeries(key) {
        const samples = seriesByKey.get(key) || [];
        dashboard.querySelectorAll(`[data-sparkline="${key}"]`).forEach((svg) => {
            const latencyLayer = svg.querySelector("[data-series]");
            const lossLayer = svg.querySelector("[data-loss-series]");
            if (!latencyLayer || !lossLayer || samples.length === 0) {
                return;
            }

            latencyLayer.replaceChildren();
            lossLayer.replaceChildren();
            const viewBox = svg.viewBox.baseVal;
            const width = viewBox.width || 100;
            const height = viewBox.height || 28;
            const horizontalPadding = width > 100 ? 4 : 1;
            const verticalPadding = height > 50 ? 12 : 3;
            const finiteLatencies = samples
                .map((sample) => sample.latencyMilliseconds)
                .filter(Number.isFinite);
            const maximum = Math.max(...finiteLatencies, 1);
            const range = maximum * 1.15;
            const coordinates = samples.map((sample, index) => {
                const x = samples.length === 1
                    ? width - horizontalPadding
                    : horizontalPadding + (
                        index * (width - horizontalPadding * 2)
                    ) / (samples.length - 1);
                if (!Number.isFinite(sample.latencyMilliseconds)) {
                    return {x, y: null};
                }
                const normalized = sample.latencyMilliseconds / range;
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
                const hasPacketLoss = (
                    samples[index - 1].lossPercent > 0
                    || samples[index].lossPercent > 0
                );
                latencyLayer.append(createSvgElement(
                    "line",
                    `chart-segment ${hasPacketLoss ? "chart-segment-loss" : "chart-segment-clean"}`,
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
                const isTotalLoss = (
                    sample.lossPercent >= 100
                    || coordinate.y === null
                );
                if (isTotalLoss) {
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

            updateChartDescription(svg, samples);
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
                addSeriesPoint(
                    node.id,
                    node.average_latency_ms,
                    node.loss_percent,
                );
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
            addSeriesPoint(
                "internet",
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
