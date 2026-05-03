from django.shortcuts import render

from .forms import IPReportForm
from .services import build_ip_report


def index(request):
    form = IPReportForm(request.GET or None)
    report = None

    if form.is_valid():
        report = build_ip_report(form.cleaned_data['ip_address'])

    return render(request, 'dashboard/index.html', {'form': form, 'report': report})
