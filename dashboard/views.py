from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.urls import reverse, NoReverseMatch
from django.utils import timezone
from django.db.models import Count
from django.db.models.functions import TruncHour, TruncDate
from datetime import timedelta

from accounts.access import role_required
from traffic.models import TrafficLog
from alerts.models import Alert


def get_system_status():
    """
    Determines whether the traffic logging engine is actively recording.
    Returns a dict with 'label' and 'css' keys for template rendering.
    """
    five_minutes_ago = timezone.now() - timedelta(minutes=5)
    recent_exists = TrafficLog.objects.filter(timestamp__gte=five_minutes_ago).exists()
    return {"label": "Operational", "css": "success"} if recent_exists else {"label": "Idle", "css": "warning"}


def get_traffic_health(active_alerts, req_per_min, threshold, violations_count):
    """
    Computes a four-level Traffic Health indicator shown in the dashboard.

    The health level is derived from four independent signals:
      1. active_alerts     — direct evidence of detected threats (unresolved alerts)
      2. req_per_min       — total site-wide requests in the last 60 seconds
                             compared against the configured spike threshold.
      3. threshold         — the configured request rate spike threshold.
      4. violations_count  — rate-limit violations recorded in the last 60 seconds.

    Levels (worst takes priority):
      CRITICAL — 5+ active alerts OR traffic > 3× threshold OR 10+ rate-limit violations
      HIGH     — 3–4 active alerts OR traffic > 1.5× threshold OR 5-9 rate-limit violations
      MODERATE — 1–2 active alerts OR traffic > 0.75× threshold OR 1-4 rate-limit violations
      NORMAL   — 0 active alerts AND traffic <= threshold AND 0 rate-limit violations

    Returns a dict with label, level (css class suffix), color, bg, border, icon, and description.
    """
    if active_alerts >= 5 or (threshold > 0 and req_per_min > threshold * 3) or violations_count >= 10:
        return {
            'level':   'critical',
            'label':   'Critical',
            'color':   '#ef4444',
            'bg':      'rgba(239,68,68,0.12)',
            'border':  'rgba(239,68,68,0.35)',
            'icon':    'bi-exclamation-octagon-fill',
            'message': 'Active DDoS pattern detected or severe rate violations — immediate action required.',
        }
    if active_alerts >= 3 or (threshold > 0 and req_per_min > threshold * 1.5) or violations_count >= 5:
        return {
            'level':   'high',
            'label':   'High',
            'color':   '#f97316',
            'bg':      'rgba(249,115,22,0.10)',
            'border':  'rgba(249,115,22,0.35)',
            'icon':    'bi-exclamation-triangle-fill',
            'message': 'Elevated traffic or multiple rate violations detected — monitor closely.',
        }
    if active_alerts >= 1 or (threshold > 0 and req_per_min > threshold * 0.75) or violations_count >= 1:
        return {
            'level':   'moderate',
            'label':   'Moderate',
            'color':   '#f59e0b',
            'bg':      'rgba(245,158,11,0.10)',
            'border':  'rgba(245,158,11,0.30)',
            'icon':    'bi-dash-circle-fill',
            'message': 'Traffic or rate limits slightly above baseline — no immediate threat.',
        }
    return {
        'level':   'normal',
        'label':   'Normal',
        'color':   '#22c55e',
        'bg':      'rgba(34,197,94,0.08)',
        'border':  'rgba(34,197,94,0.25)',
        'icon':    'bi-shield-check',
        'message': 'All systems nominal — no threats detected.',
    }


def get_dashboard_stats():
    """Shared KPI queries used by the dashboard view and JSON API."""
    from django.core.cache import cache
    cache_key = "dashboard_stats"
    stats = cache.get(cache_key)
    if stats is None:
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        stats = {
            'total_requests': TrafficLog.objects.count(),
            'today_requests': TrafficLog.objects.filter(timestamp__gte=today_start).count(),
            'unique_ips': TrafficLog.objects.values('ip_address').distinct().count(),
            'active_alerts': Alert.objects.filter(resolved=False).count(),
            'system_status': get_system_status(),
        }
        cache.set(cache_key, stats, timeout=10)  # Cache for 10 seconds
    return stats


def serialize_traffic_log(log):
    return {
        'ip_address': log.ip_address,
        'request_method': log.request_method,
        'url_accessed': log.url_accessed,
        'timestamp': log.timestamp.strftime('%H:%M:%S %d %b %Y'),
    }


def serialize_alert(alert):
    return {
        'ip_address': alert.ip_address,
        'request_count': alert.request_count,
        'severity': alert.severity,
        'resolved': alert.resolved,
        'timestamp': alert.timestamp.strftime('%H:%M %d/%m'),
    }


def get_alert_severity_counts():
    return {
        'critical': Alert.objects.filter(severity='critical').count(),
        'high': Alert.objects.filter(severity='high').count(),
        'medium': Alert.objects.filter(severity='medium').count(),
        'low': Alert.objects.filter(severity='low').count(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Dashboard View
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def dashboard(request):
    """
    Main dashboard view — collects KPI data and recent records.
    'active_alerts' is injected globally by the context processor,
    but we still query recent_traffic and recent_alerts here for the tables.
    """
    stats = get_dashboard_stats()
    recent_traffic = TrafficLog.objects.order_by('-timestamp')[:10]
    recent_alerts = Alert.objects.order_by('-timestamp')[:5]

    context = {
        **stats,
        'recent_traffic':    recent_traffic,
        'recent_alerts':     recent_alerts,
        'dashboard_data_url': _dashboard_data_url(),
        'recent_stats_url':  _recent_stats_url(),
    }
    return render(request, 'dashboard/dashboard.html', context)


def _dashboard_data_url():
    try:
        return reverse('dashboard_data')
    except NoReverseMatch:
        return '/dashboard/data/'


def _recent_stats_url():
    try:
        return reverse('dashboard_recent_stats')
    except NoReverseMatch:
        return '/dashboard/recent-stats/'


@login_required
def dashboard_recent_stats(request):
    """
    JSON API endpoint for the dashboard stats widgets (recent traffic snapshot).
    Reads the latest pre-calculated MonitoringSnapshot from the database.
    Falls back to on-the-fly calculation if the background monitoring daemon is not running.
    """
    from alerts.models import MonitoringSnapshot
    import json

    snapshot = MonitoringSnapshot.objects.order_by('-timestamp').first()
    if snapshot:
        try:
            top_ips = json.loads(snapshot.top_ips_json)
        except Exception:
            top_ips = []
        try:
            health = json.loads(snapshot.health)
        except Exception:
            health = {}

        return JsonResponse({
            'req_per_min': snapshot.req_per_min,
            'threshold':   snapshot.threshold,
            'top_ips':     top_ips,
            'health':      health,
        })

    # ── Fallback: On-the-fly calculation (if background command is not running) ──
    from alerts.models import SystemSettings, IPBlocklist, RateLimitViolation

    settings   = SystemSettings.get_settings()
    threshold  = settings.request_threshold
    now        = timezone.now()
    window_60s = now - timedelta(seconds=60)

    req_per_min = TrafficLog.objects.filter(timestamp__gte=window_60s).count()

    top_ips_qs = (
        TrafficLog.objects
        .filter(timestamp__gte=window_60s)
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    top_ips = list(top_ips_qs)
    max_count = top_ips[0]['count'] if top_ips else 1

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
        .filter(timestamp__gte=window_60s)
        .values_list('ip_address', flat=True)
    )

    ip_rows = []
    for entry in top_ips:
        ip = entry['ip_address']
        count = entry['count']
        
        if ip in blocked_ips:
            status = 'blocked'
        elif ip in alerted_ips:
            status = 'alert'
        elif ip in violated_ips:
            status = 'rate_limit'
        else:
            status = 'normal'
            
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

    active_alerts = Alert.objects.filter(resolved=False).count()
    violations_count = RateLimitViolation.objects.filter(timestamp__gte=window_60s).count()
    health = get_traffic_health(active_alerts, req_per_min, threshold, violations_count)

    return JsonResponse({
        'req_per_min': req_per_min,
        'threshold':   threshold,
        'top_ips':     ip_rows,
        'health':      health,
    })


@login_required
def dashboard_data(request):
    """
    JSON API endpoint for dashboard polling.
    Returns KPI counters, system status, and recent traffic/alert rows,
    as well as the unified chronological activity feed.
    """
    from alerts.models import IPBlocklist, RateLimitViolation

    stats = get_dashboard_stats()
    recent_traffic = TrafficLog.objects.order_by('-timestamp')[:15]
    recent_alerts = Alert.objects.order_by('-timestamp')[:10]
    recent_blocks = IPBlocklist.objects.order_by('-added_at')[:10]
    recent_violations = RateLimitViolation.objects.order_by('-timestamp')[:10]

    # ── Compile Unified Live Activity Feed ────────────────────────────────
    feed = []

    # 1. Traffic Logs (Requests)
    for log in recent_traffic:
        feed.append({
            'type':      'request',
            'timestamp': log.timestamp,
            'ip':        log.ip_address,
            'message':   f"Incoming request: {log.request_method} {log.url_accessed}",
            'icon':      'bi-arrow-right-short',
            'css':       'info',
        })

    # 2. Alerts (New and Resolved)
    for alert in recent_alerts:
        if alert.resolved:
            feed.append({
                'type':      'alert_resolved',
                'timestamp': alert.timestamp,
                'ip':        alert.ip_address,
                'message':   f"Alert resolved: {alert.ip_address} — {alert.get_detection_type_display()}",
                'icon':      'bi-shield-check',
                'css':       'success',
            })
        else:
            feed.append({
                'type':      'alert_new',
                'timestamp': alert.timestamp,
                'ip':        alert.ip_address,
                'message':   f"New alert generated: {alert.message}",
                'icon':      'bi-bell-fill',
                'css':       'danger',
            })

    # 3. Blocked IPs
    for block in recent_blocks:
        feed.append({
            'type':      'blocked_ip',
            'timestamp': block.added_at,
            'ip':        block.ip_address,
            'message':   f"IP Blocked: {block.ip_address} — Reason: {block.reason or 'No reason provided'}",
            'icon':      'bi-slash-circle-fill',
            'css':       'secondary',
        })

    # 4. Rate Limit Violations
    for violation in recent_violations:
        feed.append({
            'type':      'rate_violation',
            'timestamp': violation.timestamp,
            'ip':        violation.ip_address,
            'message':   f"Rate limit violation: {violation.ip_address} exceeded limits on {violation.path}",
            'icon':      'bi-speedometer2',
            'css':       'warning',
        })

    # Sort chronological (newest first)
    feed.sort(key=lambda x: x['timestamp'], reverse=True)

    # Limit to top 15 events
    feed = feed[:15]

    serialized_feed = []
    for item in feed:
        serialized_feed.append({
            'type':      item['type'],
            'timestamp': item['timestamp'].strftime('%H:%M:%S'),
            'ip':        item['ip'],
            'message':   item['message'],
            'icon':      item['icon'],
            'css':       item['css'],
        })

    return JsonResponse({
        **stats,
        'recent_traffic': [serialize_traffic_log(log) for log in recent_traffic[:10]],
        'recent_alerts': [serialize_alert(alert) for alert in recent_alerts[:5]],
        'activity_feed': serialized_feed,
    })


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Analytics Views
# ─────────────────────────────────────────────────────────────────────────────

@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Analytics is limited to Administrators and Security Analysts.')
def analytics(request):
    """
    Traffic Analytics page.
    Passes pre-computed table data (top IPs, URLs, severity breakdown)
    to the template. Chart data is fetched separately via the JSON API.
    """
    ip_address = request.GET.get('ip_address', '').strip()
    request_method = request.GET.get('request_method', '').strip().upper()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()

    traffic_qs = TrafficLog.objects.all()
    alerts_qs = Alert.objects.all()

    if ip_address:
        traffic_qs = traffic_qs.filter(ip_address__icontains=ip_address)
        alerts_qs = alerts_qs.filter(ip_address__icontains=ip_address)
    
    if request_method in ('GET', 'POST', 'PUT', 'DELETE'):
        traffic_qs = traffic_qs.filter(request_method=request_method)

    if date_from:
        traffic_qs = traffic_qs.filter(timestamp__date__gte=date_from)
        alerts_qs = alerts_qs.filter(timestamp__date__gte=date_from)
    if date_to:
        traffic_qs = traffic_qs.filter(timestamp__date__lte=date_to)
        alerts_qs = alerts_qs.filter(timestamp__date__lte=date_to)

    # Top 10 IPs by total request count (all time / filtered)
    top_ips = (
        traffic_qs
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    # Top 10 most accessed URLs (all time / filtered)
    top_urls = (
        traffic_qs
        .values('url_accessed')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    # Alert severity counts (filtered)
    alert_severity = {
        'critical': alerts_qs.filter(severity='critical').count(),
        'high': alerts_qs.filter(severity='high').count(),
        'medium': alerts_qs.filter(severity='medium').count(),
        'low': alerts_qs.filter(severity='low').count(),
    }

    # Method breakdown (GET vs POST / filtered)
    method_counts = (
        traffic_qs
        .values('request_method')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    context = {
        'top_ips': top_ips,
        'top_urls': top_urls,
        'alert_severity': alert_severity,
        'method_counts': method_counts,
        'total_requests': traffic_qs.count(),
        'total_alerts': alerts_qs.count(),
        'ip_address': ip_address,
        'request_method': request_method,
        'date_from': date_from,
        'date_to': date_to,
    }
    return render(request, 'dashboard/analytics.html', context)


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Analytics data is limited to Administrators and Security Analysts.')
def analytics_data(request):
    """
    JSON API endpoint — returns time-series data for Chart.js charts.

    Called by the analytics page via fetch() (AJAX), not by a browser
    navigation. Returns all chart datasets in a single HTTP request
    to minimize round-trips.

    Cybersecurity value:
    - Hourly data reveals DDoS spikes (sudden vertical surges)
    - Daily data shows traffic trends over the week
    - Alert frequency data correlates with traffic spikes visually
    """
    ip_address = request.GET.get('ip_address', '').strip()
    request_method = request.GET.get('request_method', '').strip().upper()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()

    traffic_qs = TrafficLog.objects.all()
    alerts_qs = Alert.objects.all()

    if ip_address:
        traffic_qs = traffic_qs.filter(ip_address__icontains=ip_address)
        alerts_qs = alerts_qs.filter(ip_address__icontains=ip_address)
    
    if request_method in ('GET', 'POST', 'PUT', 'DELETE'):
        traffic_qs = traffic_qs.filter(request_method=request_method)

    if date_from:
        traffic_qs = traffic_qs.filter(timestamp__date__gte=date_from)
        alerts_qs = alerts_qs.filter(timestamp__date__gte=date_from)
    if date_to:
        traffic_qs = traffic_qs.filter(timestamp__date__lte=date_to)
        alerts_qs = alerts_qs.filter(timestamp__date__lte=date_to)

    now = timezone.now()
    twenty_four_hours_ago = now - timedelta(hours=24)
    seven_days_ago = now - timedelta(days=7)

    # ── Filter boundaries: default to 24h/7d if no dates provided ────────
    if not date_from and not date_to:
        traffic_hourly_base = traffic_qs.filter(timestamp__gte=twenty_four_hours_ago)
        traffic_daily_base = traffic_qs.filter(timestamp__gte=seven_days_ago)
        alerts_daily_base = alerts_qs.filter(timestamp__gte=seven_days_ago)
    else:
        traffic_hourly_base = traffic_qs
        traffic_daily_base = traffic_qs
        alerts_daily_base = alerts_qs

    # ── Requests Per Hour ────────────────────────────────────────────────
    hourly_qs = (
        traffic_hourly_base
        .annotate(hour=TruncHour('timestamp'))
        .values('hour')
        .annotate(count=Count('id'))
        .order_by('hour')
    )

    # ── Requests Per Day ─────────────────────────────────────────────────
    daily_qs = (
        traffic_daily_base
        .annotate(day=TruncDate('timestamp'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    # ── Alert Frequency Per Day ──────────────────────────────────────────
    alerts_daily_qs = (
        alerts_daily_base
        .annotate(day=TruncDate('timestamp'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    # ── Top 10 Source IPs ────────────────────────────────────────────────
    top_ips_qs = (
        traffic_qs
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    # Alert severity counts (filtered)
    alert_severity = {
        'critical': alerts_qs.filter(severity='critical').count(),
        'high': alerts_qs.filter(severity='high').count(),
        'medium': alerts_qs.filter(severity='medium').count(),
        'low': alerts_qs.filter(severity='low').count(),
    }

    return JsonResponse({
        'hourly': [
            {
                'label': entry['hour'].strftime('%H:00') if entry['hour'] else '??',
                'count': entry['count']
            }
            for entry in hourly_qs
        ],
        'daily': [
            {
                'label': entry['day'].strftime('%b %d') if entry['day'] else '??',
                'count': entry['count']
            }
            for entry in daily_qs
        ],
        'alerts_daily': [
            {
                'label': entry['day'].strftime('%b %d') if entry['day'] else '??',
                'count': entry['count']
            }
            for entry in alerts_daily_qs
        ],
        'top_ips': [
            {'ip': entry['ip_address'], 'count': entry['count']}
            for entry in top_ips_qs
        ],
        'alert_severity': alert_severity,
        'total_requests': traffic_qs.count(),
        'total_alerts': alerts_qs.count(),
    })
