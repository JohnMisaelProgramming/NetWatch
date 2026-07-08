"""
alerts/utils.py — Shared utility functions for NetWatch alerts.

Extracts common logic used across the detector daemon, dashboard views,
and investigation center to avoid code duplication (DRY principle).
"""
from datetime import timedelta
from django.db.models import Count
from django.utils import timezone

from alerts.models import Alert, RateLimitViolation, IPBlocklist


def compute_ip_rows(window_seconds=60):
    """
    Compute the top-10 IP activity rows with status and risk indicators.

    This logic was previously duplicated in:
      - run_detector.py (L113-L144)
      - dashboard/views.py (L232-L262)

    Returns:
        tuple: (ip_rows list, req_per_min int)
            ip_rows: List of dicts with keys: ip, count, pct, pct_total, status, risk
            req_per_min: Total requests in the time window
    """
    now = timezone.now()
    window_start = now - timedelta(seconds=window_seconds)

    req_per_min = 0
    from traffic.models import TrafficLog
    req_per_min = TrafficLog.objects.filter(timestamp__gte=window_start).count()

    # Top 10 IPs in the window
    top_ips_qs = (
        TrafficLog.objects
        .filter(timestamp__gte=window_start)
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    top_ips = list(top_ips_qs)
    max_count = top_ips[0]['count'] if top_ips else 1

    # Pre-fetch status sets for efficient lookups
    alerted_ips = set(
        Alert.objects
        .filter(resolved=False)
        .values_list('ip_address', flat=True)
    )
    blocked_ips = set(
        IPBlocklist.objects.values_list('ip_address', flat=True)
    )
    violated_ips = set(
        RateLimitViolation.objects
        .filter(timestamp__gte=window_start)
        .values_list('ip_address', flat=True)
    )

    ip_rows = []
    for entry in top_ips:
        ip = entry['ip_address']
        count = entry['count']

        # Determine IP status
        if ip in blocked_ips:
            status = 'blocked'
        elif ip in alerted_ips:
            status = 'alert'
        elif ip in violated_ips:
            status = 'rate_limit'
        else:
            status = 'normal'

        # Risk Indicator Algorithm
        if status == 'blocked' or count >= 100:
            risk = 'critical'
        elif status == 'alert' or count >= 50:
            risk = 'high'
        elif status == 'rate_limit' or count >= 20:
            risk = 'medium'
        else:
            risk = 'low'

        ip_rows.append({
            'ip':        ip,
            'count':     count,
            'pct':       round(count / max_count * 100),
            'pct_total': round(count / req_per_min * 100) if req_per_min > 0 else 0,
            'status':    status,
            'risk':      risk,
        })

    return ip_rows, req_per_min
