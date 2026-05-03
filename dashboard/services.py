import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

import requests
from django.core.cache import cache


REQUEST_TIMEOUT = 14
DAY_SECONDS = 60 * 60 * 24
MINUTE_SECONDS = 60


@dataclass(frozen=True)
class SourceResult:
    name: str
    status: str
    score: int | None
    summary: dict[str, Any]
    details: dict[str, Any]
    error: str = ''

    @property
    def available(self) -> bool:
        return self.status == 'ok'


def build_ip_report(indicator: str) -> dict[str, Any]:
    target = _build_target(indicator)
    sources = _collect_sources(target)
    available_scores = [source.score for source in sources if source.score is not None]
    overall_score = round(sum(available_scores) / len(available_scores)) if available_scores else None

    return {
        'ip_address': target['value'],
        'display_value': target['value'],
        'indicator_kind': target['kind'],
        'ip_version': target.get('ip_version'),
        'resolved_ip': target.get('resolved_ip') or '',
        'overall_score': overall_score,
        'risk_level': _risk_level(overall_score),
        'sources': sources,
        'highlights': _build_highlights(sources),
        'map': _build_map(target, sources),
        'combined': _build_combined_report(sources),
    }


def _build_target(indicator: str) -> dict[str, Any]:
    try:
        ip_obj = ipaddress.ip_address(indicator)
        return {
            'kind': 'ip',
            'value': str(ip_obj),
            'ip_version': ip_obj.version,
            'resolved_ip': str(ip_obj),
        }
    except ValueError:
        domain = indicator.lower().rstrip('.')
        return {
            'kind': 'domain',
            'value': domain,
            'ip_version': None,
            'resolved_ip': _resolve_domain(domain),
        }


def _collect_sources(target: dict[str, Any]) -> list[SourceResult]:
    jobs = {
        'virustotal': lambda: _query_virustotal(target),
        'abuseipdb': lambda: _query_abuseipdb(target),
        'alienvault': lambda: _query_alienvault(target),
    }
    results: dict[str, SourceResult] = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_map = {executor.submit(job): key for key, job in jobs.items()}
        for future in as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = SourceResult(
                    name=_source_name(key),
                    status='error',
                    score=None,
                    summary={},
                    details={},
                    error=f'Unexpected error: {exc}',
                )

    return [results[key] for key in ('virustotal', 'abuseipdb', 'alienvault')]


def _query_virustotal(target: dict[str, Any]) -> SourceResult:
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not api_key:
        return _missing_key('VirusTotal', 'VIRUSTOTAL_API_KEY')
    if not _consume_limit('virustotal_minute', _env_int('VIRUSTOTAL_MINUTE_LIMIT', 4), MINUTE_SECONDS):
        return _rate_limited('VirusTotal')
    if not _consume_limit('virustotal_day', _env_int('VIRUSTOTAL_DAILY_LIMIT', 450), DAY_SECONDS):
        return _rate_limited('VirusTotal')

    path = 'ip_addresses' if target['kind'] == 'ip' else 'domains'
    response = _get_json(
        f'https://www.virustotal.com/api/v3/{path}/{target["value"]}',
        headers={'x-apikey': api_key, 'Accept': 'application/json'},
    )
    if response['error']:
        return _source_error('VirusTotal', response)

    attrs = response['data'].get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {}) or {}
    malicious = int(stats.get('malicious') or 0)
    suspicious = int(stats.get('suspicious') or 0)
    reputation = int(attrs.get('reputation') or 0)
    penalty = max(0, -reputation // 2)
    score = min(100, (malicious * 12) + (suspicious * 7) + penalty)
    country = attrs.get('country') or ''
    registrar = attrs.get('registrar') or ''
    categories = attrs.get('categories') or {}

    return SourceResult(
        name='VirusTotal',
        status='ok',
        score=score,
        summary={
            'Malicious vendors': malicious,
            'Suspicious vendors': suspicious,
            'Reputation': reputation,
            'Country': country or 'Unknown',
            'ASN owner': attrs.get('as_owner') or 'Unknown',
            'Registrar': registrar or 'Unknown',
        },
        details={
            'analysis_stats': stats,
            'tags': attrs.get('tags', [])[:10],
            'categories': list(categories.values())[:8] if isinstance(categories, dict) else [],
            'country_code': country,
            'network': attrs.get('network') or '',
            'regional_registry': attrs.get('regional_internet_registry') or '',
            'whois': _truncate(attrs.get('whois') or '', 700),
        },
    )


def _query_abuseipdb(target: dict[str, Any]) -> SourceResult:
    ip_address = target.get('resolved_ip') or ''
    if not ip_address:
        return SourceResult(
            name='AbuseIPDB',
            status='unavailable',
            score=None,
            summary={},
            details={},
            error='No resolved IP address was available for this indicator.',
        )

    api_key = os.getenv('ABUSEIPDB_API_KEY', '').strip()
    if not api_key:
        return _missing_key('AbuseIPDB', 'ABUSEIPDB_API_KEY')
    if not _consume_limit('abuseipdb_day', _env_int('ABUSEIPDB_DAILY_LIMIT', 900), DAY_SECONDS):
        return _rate_limited('AbuseIPDB')

    response = _get_json(
        'https://api.abuseipdb.com/api/v2/check',
        headers={'Key': api_key, 'Accept': 'application/json'},
        params={'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': ''},
    )
    if response['error']:
        return _source_error('AbuseIPDB', response)

    data = response['data'].get('data', {})
    score = int(data.get('abuseConfidenceScore') or 0)
    reports = data.get('reports') or []

    return SourceResult(
        name='AbuseIPDB',
        status='ok',
        score=score,
        summary={
            'Abuse confidence': f'{score}%',
            'Total reports': data.get('totalReports') or 0,
            'Whitelisted': 'Yes' if data.get('isWhitelisted') else 'No',
            'ISP': data.get('isp') or 'Unknown',
            'Usage type': data.get('usageType') or 'Unknown',
        },
        details={
            'country': data.get('countryCode') or 'Unknown',
            'country_code': data.get('countryCode') or '',
            'domain': data.get('domain') or '',
            'last_reported_at': data.get('lastReportedAt') or '',
            'recent_reports': reports[:5],
        },
    )


def _query_alienvault(target: dict[str, Any]) -> SourceResult:
    api_key = os.getenv('ALIENVAULT_API_KEY', '').strip()
    if not api_key:
        return _missing_key('AlienVault OTX', 'ALIENVAULT_API_KEY')
    if not _consume_limit('alienvault_day', _env_int('ALIENVAULT_DAILY_LIMIT', 900), DAY_SECONDS):
        return _rate_limited('AlienVault OTX')

    if target['kind'] == 'domain':
        indicator_type = 'domain'
    else:
        indicator_type = 'IPv6' if target['ip_version'] == 6 else 'IPv4'

    response = _get_json(
        f'https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target["value"]}/general',
        headers={'X-OTX-API-KEY': api_key, 'Accept': 'application/json'},
    )
    if response['error']:
        return _source_error('AlienVault OTX', response)

    data = response['data']
    pulse_info = data.get('pulse_info') or {}
    pulses = pulse_info.get('pulses') or []
    pulse_count = int(pulse_info.get('count') or data.get('pulse_count') or len(pulses) or 0)
    score = min(100, pulse_count * 15)

    return SourceResult(
        name='AlienVault OTX',
        status='ok',
        score=score,
        summary={
            'Pulse count': pulse_count,
            'Indicator type': data.get('type') or indicator_type,
            'Country': data.get('country_name') or data.get('country_code') or 'Unknown',
            'ASN': data.get('asn') or 'Unknown',
            'City': data.get('city') or 'Unknown',
        },
        details={
            'sections': data.get('sections') or [],
            'reputation': data.get('reputation') or 0,
            'country_code': data.get('country_code') or '',
            'domain': target['value'] if target['kind'] == 'domain' else '',
            'location': {
                'lat': _as_float(data.get('latitude') or data.get('lat')),
                'lon': _as_float(data.get('longitude') or data.get('lon')),
                'city': data.get('city') or '',
                'country': data.get('country_name') or data.get('country_code') or '',
            },
            'pulses': [
                {
                    'name': pulse.get('name', 'Untitled pulse'),
                    'author': pulse.get('author_name') or 'Unknown',
                    'modified': pulse.get('modified') or '',
                    'tags': pulse.get('tags') or [],
                }
                for pulse in pulses[:5]
            ],
        },
    )


def _get_json(url: str, headers: dict[str, str], params: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code >= 400:
            return {
                'error': f'HTTP {response.status_code}: {_response_message(response)}',
                'data': {},
                'headers': dict(response.headers),
            }
        return {'error': '', 'data': response.json(), 'headers': dict(response.headers)}
    except requests.Timeout:
        return {'error': 'The API request timed out.', 'data': {}, 'headers': {}}
    except requests.RequestException as exc:
        return {'error': f'Network error: {exc}', 'data': {}, 'headers': {}}
    except ValueError:
        return {'error': 'The API returned non-JSON data.', 'data': {}, 'headers': {}}


def _response_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return _truncate(response.text.strip(), 180) or response.reason

    if isinstance(payload, dict):
        error = payload.get('error')
        if isinstance(error, dict):
            return str(error.get('message') or error.get('code') or response.reason)
        if isinstance(error, str):
            return error
        errors = payload.get('errors')
        if errors:
            return _truncate(str(errors), 180)
    return response.reason


def _source_error(name: str, response: dict[str, Any]) -> SourceResult:
    return SourceResult(name=name, status='error', score=None, summary={}, details={}, error=response['error'])


def _missing_key(name: str, env_var: str) -> SourceResult:
    return SourceResult(
        name=name,
        status='missing_key',
        score=None,
        summary={},
        details={},
        error=f'Set {env_var} in your environment to enable this source.',
    )


def _rate_limited(name: str) -> SourceResult:
    return SourceResult(
        name=name,
        status='rate_limited',
        score=None,
        summary={},
        details={},
        error='Internal request limit reached for this provider. Try again later.',
    )


def _consume_limit(name: str, limit: int, timeout: int) -> bool:
    if limit <= 0:
        return True
    key = f'provider-limit:{name}'
    added = cache.add(key, 1, timeout)
    if added:
        return True
    try:
        value = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout)
        return True
    return value <= limit


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _build_highlights(sources: list[SourceResult]) -> list[str]:
    highlights: list[str] = []
    for source in sources:
        if not source.available:
            continue
        if source.name == 'VirusTotal':
            malicious = source.summary.get('Malicious vendors', 0)
            suspicious = source.summary.get('Suspicious vendors', 0)
            highlights.append(f'{malicious} malicious and {suspicious} suspicious detections were observed.')
        elif source.name == 'AbuseIPDB':
            highlights.append(
                f'{source.summary.get("Abuse confidence")} abuse confidence across '
                f'{source.summary.get("Total reports")} reports.'
            )
        elif source.name == 'AlienVault OTX':
            highlights.append(f'{source.summary.get("Pulse count")} related threat collections were found.')

    return highlights or ['Live intelligence is unavailable right now.']


def _build_combined_report(sources: list[SourceResult]) -> dict[str, Any]:
    verdicts = _source_by_name(sources, 'VirusTotal')
    abuse = _source_by_name(sources, 'AbuseIPDB')
    threat_collections = _source_by_name(sources, 'AlienVault OTX')

    facts = [
        {'label': 'Country', 'value': _first_value(sources, 'Country', 'country')},
        {'label': 'ASN / owner', 'value': _first_value(sources, 'ASN owner', 'ASN')},
        {'label': 'ISP', 'value': _summary_value(abuse, 'ISP')},
        {'label': 'Usage type', 'value': _summary_value(abuse, 'Usage type')},
        {'label': 'Network', 'value': _detail_value(verdicts, 'network')},
        {'label': 'Domain', 'value': _detail_value(abuse, 'domain') or _detail_value(threat_collections, 'domain')},
        {'label': 'Registrar', 'value': _summary_value(verdicts, 'Registrar')},
        {'label': 'Whitelisted', 'value': _summary_value(abuse, 'Whitelisted')},
        {'label': 'Last reported', 'value': _detail_value(abuse, 'last_reported_at')},
    ]

    return {
        'facts': [fact for fact in facts if fact['value'] and fact['value'] != 'Unknown'],
        'analysis_stats': _detail_value(verdicts, 'analysis_stats') or {},
        'tags': (_detail_value(verdicts, 'tags') or []) + (_detail_value(verdicts, 'categories') or []),
        'recent_reports': _detail_value(abuse, 'recent_reports') or [],
        'collections': _detail_value(threat_collections, 'pulses') or [],
    }


def _source_by_name(sources: list[SourceResult], name: str) -> SourceResult | None:
    return next((source for source in sources if source.name == name and source.available), None)


def _summary_value(source: SourceResult | None, key: str) -> Any:
    if not source:
        return ''
    return source.summary.get(key) or ''


def _detail_value(source: SourceResult | None, key: str) -> Any:
    if not source:
        return ''
    return source.details.get(key) or ''


def _first_value(sources: list[SourceResult], *keys: str) -> Any:
    for source in sources:
        if not source.available:
            continue
        for key in keys:
            value = source.summary.get(key) or source.details.get(key)
            if value and value != 'Unknown':
                return value
    return ''


def _build_map(target: dict[str, Any], sources: list[SourceResult]) -> dict[str, Any]:
    country_code = ''
    country_label = ''
    for source in sources:
        if not source.available:
            continue
        candidate = source.details.get('country_code') or source.summary.get('Country')
        if candidate and candidate != 'Unknown':
            country_code = str(candidate).upper()
            country_label = str(source.summary.get('Country') or candidate)
            break

    centroid = COUNTRY_CENTROIDS.get(country_code)
    if centroid:
        lat, lon, label = centroid
        return _map_payload(target['value'], lat, lon, '', country_label or label, 'country marker')

    return {
        'available': False,
        'label': 'Location unavailable',
        'precision': 'none',
        'x': 50,
        'y': 50,
        'lat': '',
        'lon': '',
        'ip_address': target['value'],
    }


def _map_payload(
    ip_address: str,
    lat: float,
    lon: float,
    city: str | None,
    country: str | None,
    precision: str,
) -> dict[str, Any]:
    x = max(2, min(98, ((lon + 180) / 360) * 100))
    y = max(5, min(95, ((90 - lat) / 180) * 100))
    label_parts = [part for part in (city, country) if part]
    return {
        'available': True,
        'label': ', '.join(label_parts) or 'Approximate location',
        'precision': precision,
        'x': round(x, 2),
        'y': round(y, 2),
        'lat': f'{lat:.2f}',
        'lon': f'{lon:.2f}',
        'ip_address': ip_address,
    }


def _resolve_domain(domain: str) -> str:
    try:
        addresses = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return ''

    for family in (socket.AF_INET, socket.AF_INET6):
        for address in addresses:
            if address[0] == family:
                return address[4][0]
    return ''


def _risk_level(score: int | None) -> dict[str, str]:
    if score is None:
        return {'label': 'Unknown', 'tone': 'muted'}
    if score >= 75:
        return {'label': 'Critical', 'tone': 'critical'}
    if score >= 45:
        return {'label': 'High', 'tone': 'high'}
    if score >= 20:
        return {'label': 'Moderate', 'tone': 'moderate'}
    return {'label': 'Low', 'tone': 'low'}


def _source_name(key: str) -> str:
    return {
        'virustotal': 'VirusTotal',
        'abuseipdb': 'AbuseIPDB',
        'alienvault': 'AlienVault OTX',
    }[key]


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + '...'


COUNTRY_CENTROIDS: dict[str, tuple[float, float, str]] = {
    'AE': (23.42, 53.85, 'United Arab Emirates'),
    'AR': (-38.42, -63.62, 'Argentina'),
    'AT': (47.52, 14.55, 'Austria'),
    'AU': (-25.27, 133.78, 'Australia'),
    'BE': (50.5, 4.47, 'Belgium'),
    'BG': (42.73, 25.49, 'Bulgaria'),
    'BR': (-14.24, -51.93, 'Brazil'),
    'CA': (56.13, -106.35, 'Canada'),
    'CH': (46.82, 8.23, 'Switzerland'),
    'CL': (-35.68, -71.54, 'Chile'),
    'CN': (35.86, 104.2, 'China'),
    'CO': (4.57, -74.3, 'Colombia'),
    'CZ': (49.82, 15.47, 'Czechia'),
    'DE': (51.17, 10.45, 'Germany'),
    'DK': (56.26, 9.5, 'Denmark'),
    'EG': (26.82, 30.8, 'Egypt'),
    'ES': (40.46, -3.75, 'Spain'),
    'FI': (61.92, 25.75, 'Finland'),
    'FR': (46.23, 2.21, 'France'),
    'GB': (55.38, -3.44, 'United Kingdom'),
    'GR': (39.07, 21.82, 'Greece'),
    'HK': (22.32, 114.17, 'Hong Kong'),
    'ID': (-0.79, 113.92, 'Indonesia'),
    'IE': (53.41, -8.24, 'Ireland'),
    'IL': (31.05, 34.85, 'Israel'),
    'IN': (20.59, 78.96, 'India'),
    'IQ': (33.22, 43.68, 'Iraq'),
    'IR': (32.43, 53.69, 'Iran'),
    'IT': (41.87, 12.57, 'Italy'),
    'JO': (30.59, 36.24, 'Jordan'),
    'JP': (36.2, 138.25, 'Japan'),
    'KR': (35.91, 127.77, 'South Korea'),
    'KW': (29.31, 47.48, 'Kuwait'),
    'LB': (33.85, 35.86, 'Lebanon'),
    'MX': (23.63, -102.55, 'Mexico'),
    'MY': (4.21, 101.98, 'Malaysia'),
    'NL': (52.13, 5.29, 'Netherlands'),
    'NO': (60.47, 8.47, 'Norway'),
    'NZ': (-40.9, 174.89, 'New Zealand'),
    'PK': (30.38, 69.35, 'Pakistan'),
    'PL': (51.92, 19.15, 'Poland'),
    'PT': (39.4, -8.22, 'Portugal'),
    'QA': (25.35, 51.18, 'Qatar'),
    'RO': (45.94, 24.97, 'Romania'),
    'RU': (61.52, 105.32, 'Russia'),
    'SA': (23.89, 45.08, 'Saudi Arabia'),
    'SE': (60.13, 18.64, 'Sweden'),
    'SG': (1.35, 103.82, 'Singapore'),
    'SY': (34.8, 38.99, 'Syria'),
    'TH': (15.87, 100.99, 'Thailand'),
    'TR': (38.96, 35.24, 'Turkey'),
    'TW': (23.7, 120.96, 'Taiwan'),
    'UA': (48.38, 31.17, 'Ukraine'),
    'US': (37.09, -95.71, 'United States'),
    'VN': (14.06, 108.28, 'Vietnam'),
    'ZA': (-30.56, 22.94, 'South Africa'),
}
