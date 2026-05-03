import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const REQUEST_TIMEOUT = 14000;
const DAY_MS = 24 * 60 * 60 * 1000;
const MINUTE_MS = 60 * 1000;
const counters = new Map();

export default async (request) => {
    try {
        const url = new URL(request.url);
        const rawIndicator = url.searchParams.get("indicator") || "";
        const indicator = sanitizeIndicator(rawIndicator);
        const target = await buildTarget(indicator);

        if (!target) {
            return json({ error: "Enter a valid IP address or domain." }, 400);
        }

        const report = await buildReport(target);
        return json({ report });
    } catch (error) {
        return json({ error: error.message || "Unable to build report." }, 500);
    }
};

async function buildReport(target) {
    const sources = await Promise.all([
        queryReputation(target),
        queryAbuse(target),
        queryCollections(target),
    ]);
    const scores = sources.map((source) => source.score).filter((score) => score !== null);
    const overallScore = scores.length ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length) : null;

    return {
        displayValue: target.value,
        indicatorKind: target.kind,
        ipVersion: target.ipVersion,
        resolvedIp: target.resolvedIp || "",
        overallScore,
        riskLevel: riskLevel(overallScore),
        highlights: buildHighlights(sources),
        map: buildMap(target, sources),
        combined: buildCombinedReport(sources),
    };
}

async function buildTarget(indicator) {
    if (!indicator) {
        return null;
    }
    const ipVersion = isIP(indicator);
    if (ipVersion) {
        return { kind: "ip", value: indicator, ipVersion, resolvedIp: indicator };
    }
    if (!isValidDomain(indicator)) {
        return null;
    }
    const domain = indicator.toLowerCase().replace(/\.$/, "");
    return {
        kind: "domain",
        value: domain,
        ipVersion: null,
        resolvedIp: await resolveDomain(domain),
    };
}

async function queryReputation(target) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY || "";
    if (!apiKey) {
        return sourceError("reputation", "missing_key", "Reputation data is not configured.");
    }
    if (!consumeLimit("reputation_minute", envInt("VIRUSTOTAL_MINUTE_LIMIT", 4), MINUTE_MS)) {
        return sourceError("reputation", "rate_limited", "Internal request limit reached.");
    }
    if (!consumeLimit("reputation_day", envInt("VIRUSTOTAL_DAILY_LIMIT", 450), DAY_MS)) {
        return sourceError("reputation", "rate_limited", "Internal request limit reached.");
    }

    const path = target.kind === "ip" ? "ip_addresses" : "domains";
    const response = await getJson(`https://www.virustotal.com/api/v3/${path}/${encodeURIComponent(target.value)}`, {
        "x-apikey": apiKey,
        Accept: "application/json",
    });
    if (response.error) {
        return sourceError("reputation", "error", response.error);
    }

    const attrs = response.data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const reputation = Number(attrs.reputation || 0);
    const penalty = Math.max(0, Math.floor(-reputation / 2));
    const categories = attrs.categories && typeof attrs.categories === "object" ? Object.values(attrs.categories).slice(0, 8) : [];

    return {
        name: "reputation",
        available: true,
        score: Math.min(100, malicious * 12 + suspicious * 7 + penalty),
        summary: {
            malicious,
            suspicious,
            reputation,
            country: attrs.country || "",
            asOwner: attrs.as_owner || "",
            registrar: attrs.registrar || "",
        },
        details: {
            analysisStats: stats,
            tags: (attrs.tags || []).slice(0, 10),
            categories,
            countryCode: attrs.country || "",
            network: attrs.network || "",
        },
    };
}

async function queryAbuse(target) {
    const ipAddress = target.resolvedIp || "";
    if (!ipAddress) {
        return sourceError("abuse", "unavailable", "No resolved IP address was available.");
    }
    const apiKey = process.env.ABUSEIPDB_API_KEY || "";
    if (!apiKey) {
        return sourceError("abuse", "missing_key", "Abuse history is not configured.");
    }
    if (!consumeLimit("abuse_day", envInt("ABUSEIPDB_DAILY_LIMIT", 900), DAY_MS)) {
        return sourceError("abuse", "rate_limited", "Internal request limit reached.");
    }

    const params = new URLSearchParams({ ipAddress, maxAgeInDays: "90", verbose: "" });
    const response = await getJson(`https://api.abuseipdb.com/api/v2/check?${params}`, {
        Key: apiKey,
        Accept: "application/json",
    });
    if (response.error) {
        return sourceError("abuse", "error", response.error);
    }

    const data = response.data?.data || {};
    const score = Number(data.abuseConfidenceScore || 0);
    return {
        name: "abuse",
        available: true,
        score,
        summary: {
            abuseConfidence: `${score}%`,
            totalReports: data.totalReports || 0,
            whitelisted: data.isWhitelisted ? "Yes" : "No",
            isp: data.isp || "",
            usageType: data.usageType || "",
        },
        details: {
            country: data.countryCode || "",
            countryCode: data.countryCode || "",
            domain: data.domain || "",
            lastReportedAt: data.lastReportedAt || "",
            recentReports: (data.reports || []).slice(0, 5),
        },
    };
}

async function queryCollections(target) {
    const apiKey = process.env.ALIENVAULT_API_KEY || "";
    if (!apiKey) {
        return sourceError("collections", "missing_key", "Threat collections are not configured.");
    }
    if (!consumeLimit("collections_day", envInt("ALIENVAULT_DAILY_LIMIT", 900), DAY_MS)) {
        return sourceError("collections", "rate_limited", "Internal request limit reached.");
    }

    const type = target.kind === "domain" ? "domain" : target.ipVersion === 6 ? "IPv6" : "IPv4";
    const response = await getJson(`https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(target.value)}/general`, {
        "X-OTX-API-KEY": apiKey,
        Accept: "application/json",
    });
    if (response.error) {
        return sourceError("collections", "error", response.error);
    }

    const data = response.data || {};
    const pulseInfo = data.pulse_info || {};
    const pulses = pulseInfo.pulses || [];
    const pulseCount = Number(pulseInfo.count || data.pulse_count || pulses.length || 0);
    return {
        name: "collections",
        available: true,
        score: Math.min(100, pulseCount * 15),
        summary: {
            pulseCount,
            country: data.country_name || data.country_code || "",
            asn: data.asn || "",
            city: data.city || "",
        },
        details: {
            countryCode: data.country_code || "",
            domain: target.kind === "domain" ? target.value : "",
            collections: pulses.slice(0, 5).map((pulse) => ({
                name: pulse.name || "Untitled collection",
                modified: pulse.modified || "",
            })),
        },
    };
}

function buildHighlights(sources) {
    const highlights = [];
    for (const source of sources) {
        if (!source.available) {
            continue;
        }
        if (source.name === "reputation") {
            highlights.push(`${source.summary.malicious} malicious and ${source.summary.suspicious} suspicious detections were observed.`);
        }
        if (source.name === "abuse") {
            highlights.push(`${source.summary.abuseConfidence} abuse confidence across ${source.summary.totalReports} reports.`);
        }
        if (source.name === "collections") {
            highlights.push(`${source.summary.pulseCount} related threat collections were found.`);
        }
    }
    return highlights.length ? highlights : ["Live intelligence is unavailable right now."];
}

function buildCombinedReport(sources) {
    const reputation = findSource(sources, "reputation");
    const abuse = findSource(sources, "abuse");
    const collections = findSource(sources, "collections");
    const facts = [
        { label: "Country", value: firstValue(sources, "country", "countryCode") },
        { label: "ASN / owner", value: reputation?.summary.asOwner || collections?.summary.asn || "" },
        { label: "ISP", value: abuse?.summary.isp || "" },
        { label: "Usage type", value: abuse?.summary.usageType || "" },
        { label: "Network", value: reputation?.details.network || "" },
        { label: "Domain", value: abuse?.details.domain || collections?.details.domain || "" },
        { label: "Registrar", value: reputation?.summary.registrar || "" },
        { label: "Whitelisted", value: abuse?.summary.whitelisted || "" },
        { label: "Last reported", value: abuse?.details.lastReportedAt || "" },
    ].filter((fact) => fact.value && fact.value !== "Unknown");

    return {
        facts,
        analysisStats: reputation?.details.analysisStats || {},
        tags: [...(reputation?.details.tags || []), ...(reputation?.details.categories || [])],
        recentReports: abuse?.details.recentReports || [],
        collections: collections?.details.collections || [],
    };
}

function buildMap(target, sources) {
    const countryCode = firstValue(sources, "countryCode").toUpperCase();
    const centroid = COUNTRY_CENTROIDS[countryCode];
    if (!centroid) {
        return {
            available: false,
            label: "Location unavailable",
            precision: "none",
            x: 50,
            y: 50,
        };
    }
    const [lat, lon, label] = centroid;
    return {
        available: true,
        label,
        precision: "country marker",
        x: Math.max(2, Math.min(98, ((lon + 180) / 360) * 100)).toFixed(2),
        y: Math.max(5, Math.min(95, ((90 - lat) / 180) * 100)).toFixed(2),
        indicator: target.value,
    };
}

function riskLevel(score) {
    if (score === null) {
        return { label: "Unknown", tone: "muted" };
    }
    if (score >= 75) {
        return { label: "Critical", tone: "critical" };
    }
    if (score >= 45) {
        return { label: "High", tone: "high" };
    }
    if (score >= 20) {
        return { label: "Moderate", tone: "moderate" };
    }
    return { label: "Low", tone: "low" };
}

function findSource(sources, name) {
    return sources.find((source) => source.name === name && source.available);
}

function firstValue(sources, ...keys) {
    for (const source of sources) {
        if (!source.available) {
            continue;
        }
        for (const key of keys) {
            const value = source.summary?.[key] || source.details?.[key];
            if (value && value !== "Unknown") {
                return String(value);
            }
        }
    }
    return "";
}

async function getJson(url, headers) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
    try {
        const response = await fetch(url, { headers, signal: controller.signal });
        const text = await response.text();
        const data = text ? JSON.parse(text) : {};
        if (!response.ok) {
            return { error: responseMessage(data, response), data: {} };
        }
        return { error: "", data };
    } catch (error) {
        return { error: error.name === "AbortError" ? "The request timed out." : `Network error: ${error.message}`, data: {} };
    } finally {
        clearTimeout(timeout);
    }
}

function responseMessage(data, response) {
    if (data?.error?.message) {
        return `HTTP ${response.status}: ${data.error.message}`;
    }
    if (typeof data?.error === "string") {
        return `HTTP ${response.status}: ${data.error}`;
    }
    return `HTTP ${response.status}: ${response.statusText}`;
}

function sourceError(name, status, message) {
    return { name, status, available: false, score: null, summary: {}, details: {}, error: message };
}

function sanitizeIndicator(value) {
    let cleaned = String(value || "").trim().replace(/^[\[\](){}<>"'`]+|[\[\](){}<>"'`,;]+$/g, "");
    try {
        const parsed = new URL(cleaned.includes("://") ? cleaned : `https://${cleaned}`);
        if (parsed.hostname) {
            cleaned = parsed.hostname;
        }
    } catch {
        // Keep the original cleaned input.
    }
    cleaned = cleaned.split(/[/?#]/, 1)[0].replace(/^[\[\](){}<>"'`]+|[\[\](){}<>"'`,;]+$/g, "");
    if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(cleaned)) {
        cleaned = cleaned.replace(/:\d+$/, "");
    }
    return cleaned;
}

function isValidDomain(value) {
    if (!value || value.length > 253 || !value.includes(".")) {
        return false;
    }
    return value.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

async function resolveDomain(domain) {
    try {
        const result = await lookup(domain);
        return result.address || "";
    } catch {
        return "";
    }
}

function consumeLimit(name, limit, windowMs) {
    if (limit <= 0) {
        return true;
    }
    const now = Date.now();
    const current = counters.get(name);
    if (!current || current.resetAt <= now) {
        counters.set(name, { count: 1, resetAt: now + windowMs });
        return true;
    }
    current.count += 1;
    return current.count <= limit;
}

function envInt(name, fallback) {
    const value = Number.parseInt(process.env[name] || "", 10);
    return Number.isFinite(value) ? value : fallback;
}

function json(payload, status = 200) {
    return new Response(JSON.stringify(payload), {
        status,
        headers: { "content-type": "application/json" },
    });
}

const COUNTRY_CENTROIDS = {
    AE: [23.42, 53.85, "United Arab Emirates"],
    AR: [-38.42, -63.62, "Argentina"],
    AT: [47.52, 14.55, "Austria"],
    AU: [-25.27, 133.78, "Australia"],
    BE: [50.5, 4.47, "Belgium"],
    BG: [42.73, 25.49, "Bulgaria"],
    BR: [-14.24, -51.93, "Brazil"],
    CA: [56.13, -106.35, "Canada"],
    CH: [46.82, 8.23, "Switzerland"],
    CL: [-35.68, -71.54, "Chile"],
    CN: [35.86, 104.2, "China"],
    CO: [4.57, -74.3, "Colombia"],
    CZ: [49.82, 15.47, "Czechia"],
    DE: [51.17, 10.45, "Germany"],
    DK: [56.26, 9.5, "Denmark"],
    EG: [26.82, 30.8, "Egypt"],
    ES: [40.46, -3.75, "Spain"],
    FI: [61.92, 25.75, "Finland"],
    FR: [46.23, 2.21, "France"],
    GB: [55.38, -3.44, "United Kingdom"],
    GR: [39.07, 21.82, "Greece"],
    HK: [22.32, 114.17, "Hong Kong"],
    ID: [-0.79, 113.92, "Indonesia"],
    IE: [53.41, -8.24, "Ireland"],
    IL: [31.05, 34.85, "Israel"],
    IN: [20.59, 78.96, "India"],
    IQ: [33.22, 43.68, "Iraq"],
    IR: [32.43, 53.69, "Iran"],
    IT: [41.87, 12.57, "Italy"],
    JO: [30.59, 36.24, "Jordan"],
    JP: [36.2, 138.25, "Japan"],
    KR: [35.91, 127.77, "South Korea"],
    KW: [29.31, 47.48, "Kuwait"],
    LB: [33.85, 35.86, "Lebanon"],
    MX: [23.63, -102.55, "Mexico"],
    MY: [4.21, 101.98, "Malaysia"],
    NL: [52.13, 5.29, "Netherlands"],
    NO: [60.47, 8.47, "Norway"],
    NZ: [-40.9, 174.89, "New Zealand"],
    PK: [30.38, 69.35, "Pakistan"],
    PL: [51.92, 19.15, "Poland"],
    PT: [39.4, -8.22, "Portugal"],
    QA: [25.35, 51.18, "Qatar"],
    RO: [45.94, 24.97, "Romania"],
    RU: [61.52, 105.32, "Russia"],
    SA: [23.89, 45.08, "Saudi Arabia"],
    SE: [60.13, 18.64, "Sweden"],
    SG: [1.35, 103.82, "Singapore"],
    SY: [34.8, 38.99, "Syria"],
    TH: [15.87, 100.99, "Thailand"],
    TR: [38.96, 35.24, "Turkey"],
    TW: [23.7, 120.96, "Taiwan"],
    UA: [48.38, 31.17, "Ukraine"],
    US: [37.09, -95.71, "United States"],
    VN: [14.06, 108.28, "Vietnam"],
    ZA: [-30.56, 22.94, "South Africa"],
};
