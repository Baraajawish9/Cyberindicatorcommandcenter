const form = document.querySelector("#search-form");
const input = document.querySelector("#indicator");
const error = document.querySelector("#field-error");
const emptyState = document.querySelector("#empty-state");
const loadingState = document.querySelector("#loading-state");
const reportRoot = document.querySelector("#report-root");
const submitButton = form.querySelector("button");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const indicator = input.value.trim();
    error.textContent = "";

    if (!indicator) {
        error.textContent = "Enter an IP address or domain.";
        return;
    }

    setLoading(true);
    try {
        const response = await fetch(`/api/report?indicator=${encodeURIComponent(indicator)}`);
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || "Unable to build report.");
        }
        renderReport(payload.report);
    } catch (requestError) {
        error.textContent = requestError.message;
        reportRoot.hidden = true;
        emptyState.hidden = false;
    } finally {
        setLoading(false);
    }
});

function setLoading(isLoading) {
    submitButton.disabled = isLoading;
    loadingState.hidden = !isLoading;
    if (isLoading) {
        emptyState.hidden = true;
        reportRoot.hidden = true;
    }
}

function renderReport(report) {
    emptyState.hidden = true;
    reportRoot.hidden = false;

    const suffix = report.indicatorKind === "ip"
        ? ` / IPv${report.ipVersion}`
        : report.resolvedIp
            ? ` / ${escapeHtml(report.resolvedIp)}`
            : "";

    reportRoot.innerHTML = `
        <section class="command-grid" aria-label="Combined report">
            <article class="risk-panel ${escapeHtml(report.riskLevel.tone)}">
                <p class="eyebrow">Combined risk</p>
                <div class="risk-layout">
                    <div class="score-ring" style="--score: ${report.overallScore ?? 0};">
                        <span>${report.overallScore ?? "--"}</span>
                    </div>
                    <div>
                        <h2>${escapeHtml(report.riskLevel.label)}</h2>
                        <p class="mono">${escapeHtml(report.displayValue)}${suffix}</p>
                    </div>
                </div>
            </article>

            <article class="map-panel">
                <header>
                    <div>
                        <p class="eyebrow">Country trace</p>
                        <h2>${escapeHtml(report.map.label)}</h2>
                    </div>
                    <span class="precision">${escapeHtml(report.map.precision)}</span>
                </header>
                <div class="world-map" style="--pin-x: ${report.map.x}%; --pin-y: ${report.map.y}%;">
                    ${report.map.available ? `<span class="map-pin" aria-label="Indicator location"></span>` : ""}
                </div>
                <footer>
                    <span>Approximate country marker</span>
                    <span class="mono">${escapeHtml(report.displayValue)}</span>
                </footer>
            </article>

            <article class="intel-panel">
                <p class="eyebrow">Key signals</p>
                <div class="highlight-stack">
                    ${report.highlights.map((item) => `<p><span></span>${escapeHtml(item)}</p>`).join("")}
                </div>
            </article>
        </section>

        <section class="combined-report" aria-label="Combined intelligence report">
            <header>
                <div>
                    <p class="eyebrow">Unified report</p>
                    <h2>Combined intelligence report</h2>
                </div>
                <span class="precision">merged</span>
            </header>
            <div class="combined-layout">
                <section class="report-section">
                    <h3>Entity profile</h3>
                    ${renderFacts(report.combined.facts)}
                </section>
                <section class="report-section">
                    <h3>Detection breakdown</h3>
                    ${renderStats(report.combined.analysisStats)}
                    ${renderTags(report.combined.tags)}
                </section>
                <section class="report-section report-section-wide">
                    <h3>Recent abuse reports</h3>
                    ${renderReports(report.combined.recentReports)}
                </section>
                <section class="report-section report-section-wide">
                    <h3>Related threat collections</h3>
                    ${renderCollections(report.combined.collections)}
                </section>
            </div>
        </section>
    `;
}

function renderFacts(facts) {
    if (!facts.length) {
        return `<p class="empty">No profile details returned.</p>`;
    }
    return `
        <dl class="facts">
            ${facts.map((fact) => `
                <div>
                    <dt>${escapeHtml(fact.label)}</dt>
                    <dd>${escapeHtml(String(fact.value))}</dd>
                </div>
            `).join("")}
        </dl>
    `;
}

function renderStats(stats) {
    const entries = Object.entries(stats || {});
    if (!entries.length) {
        return `<p class="empty">No detection breakdown returned.</p>`;
    }
    return `
        <div class="stat-bars">
            ${entries.map(([label, count]) => `
                <div class="stat-row">
                    <span>${escapeHtml(titleCase(label))}</span>
                    <div><i style="width: ${Number(count) || 0}%;"></i></div>
                    <strong>${Number(count) || 0}</strong>
                </div>
            `).join("")}
        </div>
    `;
}

function renderTags(tags) {
    if (!tags.length) {
        return "";
    }
    return `<div class="tags">${tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}</div>`;
}

function renderReports(reports) {
    if (!reports.length) {
        return `<p class="empty">No recent report comments returned.</p>`;
    }
    return `
        <ul class="report-list">
            ${reports.map((item) => `
                <li>
                    <strong>${escapeHtml(item.reportedAt || "Unknown date")}</strong>
                    <span>${escapeHtml(item.comment || "No comment provided")}</span>
                </li>
            `).join("")}
        </ul>
    `;
}

function renderCollections(collections) {
    if (!collections.length) {
        return `<p class="empty">No related threat collections returned.</p>`;
    }
    return `
        <ul class="pulse-list">
            ${collections.map((item) => `
                <li>
                    <strong>${escapeHtml(item.name || "Untitled collection")}</strong>
                    <span>${escapeHtml(item.modified || "No date")}</span>
                </li>
            `).join("")}
        </ul>
    `;
}

function titleCase(value) {
    return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
