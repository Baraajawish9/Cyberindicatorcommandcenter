import ipaddress
import re
from urllib.parse import urlparse

from django import forms


class IPReportForm(forms.Form):
    ip_address = forms.CharField(
        label='IP address or domain',
        max_length=253,
        widget=forms.TextInput(
            attrs={
                'autocomplete': 'off',
                'placeholder': '8.8.8.8, example.com, or https://example.com/path',
            }
        ),
    )

    def clean_ip_address(self):
        value = _sanitize_indicator_input(self.cleaned_data['ip_address'])
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass

        if _is_valid_domain(value):
            return value.lower()
        raise forms.ValidationError('Enter a valid IP address or domain.')


def _sanitize_indicator_input(value: str) -> str:
    value = value.strip().strip('[](){}<>"\'`')
    parsed = urlparse(value if '://' in value else f'//{value}')
    if parsed.hostname:
        value = parsed.hostname

    if '/' in value:
        value = value.split('/', 1)[0]
    if '?' in value:
        value = value.split('?', 1)[0]
    if '#' in value:
        value = value.split('#', 1)[0]

    value = value.strip().strip('[](){}<>"\'`,;')
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}:\d+', value):
        value = value.rsplit(':', 1)[0]
    return value


def _is_valid_domain(value: str) -> bool:
    value = value.rstrip('.')
    if len(value) > 253 or '.' not in value:
        return False
    labels = value.split('.')
    label_pattern = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)
    return all(label_pattern.fullmatch(label) for label in labels)
