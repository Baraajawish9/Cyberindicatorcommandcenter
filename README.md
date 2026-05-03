# Cyber Threat Intelligence Dashboard

A Django dashboard that accepts an IPv4 address, IPv6 address, or domain and combines live enrichment from:

- VirusTotal API v3
- AbuseIPDB API v2
- AlienVault OTX API v1

The report includes a combined risk score, a unified report, and a country-level world map marker.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Set the API keys in your shell:

```powershell
$env:VIRUSTOTAL_API_KEY="your-virustotal-api-key"
$env:ABUSEIPDB_API_KEY="your-abuseipdb-api-key"
$env:ALIENVAULT_API_KEY="your-alienvault-otx-api-key"
```

Run the app:

```powershell
python manage.py runserver
```

Open `http://127.0.0.1:8000/`.

## Notes

The dashboard still renders if one or more keys are missing. Each source card shows the setup or API error instead of failing the whole report.

The map intentionally uses country-level centroids, not exact IP coordinates. Domain lookups resolve the domain to an IP internally for IP-only abuse history and location context.

Provider usage limits are enforced internally and are not shown in the public dashboard. Override the defaults with `VIRUSTOTAL_DAILY_LIMIT`, `VIRUSTOTAL_MINUTE_LIMIT`, `ABUSEIPDB_DAILY_LIMIT`, and `ALIENVAULT_DAILY_LIMIT`.
