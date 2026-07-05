import time
import json
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count

from traffic.models import TrafficLog
from alerts.models import Alert, RateLimitViolation, SystemSettings, IPBlocklist, MonitoringSnapshot
from alerts.detector import detect_ddos, detect_rate_limit_violation
from dashboard.views import get_traffic_health

class Command(BaseCommand):
    help = 'Runs the standalone NetWatch network traffic monitoring and detection engine.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=5,
            help='Sleep interval between detection passes (in seconds)',
        )
        parser.add_argument(
            '--once',
            action='store_true',
            help='Run detection once and exit (useful for testing)',
        )

    def handle(self, *args, **options):
        interval = options['interval']
        once = options['once']
        self.stdout.write(self.style.SUCCESS(
            f"Starting NetWatch Monitoring Engine daemon (Interval: {interval}s)..."
        ))

        while True:
            try:
                self.run_detection_pass()
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error in detection pass: {e}"))
            
            if once:
                break
            time.sleep(interval)

    def run_detection_pass(self):
        settings = SystemSettings.get_settings()
        now = timezone.now()
        
        # Update daemon heartbeat cache
        from django.core.cache import cache
        cache.set("detector_last_run", now, timeout=60)

        # ── 1. Run detection engine for all active IPs in the sliding window ──
        max_window_mins = max(settings.time_window_minutes, settings.rate_limit_window_minutes)
        window_start = now - timedelta(minutes=max_window_mins)

        # Find distinct IPs with activity in this window
        active_ips = list(
            TrafficLog.objects
            .filter(timestamp__gte=window_start)
            .values_list('ip_address', flat=True)
            .distinct()
        )

        for ip in active_ips:
            # 1a. Run DDoS spike detection
            detect_ddos(ip, settings=settings)

            # 1b. Run Rate Limit violation detection
            # Find the latest request to get path/method metadata
            last_log = (
                TrafficLog.objects
                .filter(ip_address=ip, timestamp__gte=window_start)
                .order_by('-timestamp')
                .first()
            )
            path = last_log.url_accessed if last_log else '/'
            method = last_log.request_method if last_log else 'GET'
            detect_rate_limit_violation(ip, path, method, settings=settings)

        # ── 2. Pre-calculate dashboard statistics and write to snapshot ──
        window_60s = now - timedelta(seconds=60)

        # Site-wide request rate
        req_per_min = TrafficLog.objects.filter(timestamp__gte=window_60s).count()

        # Top 10 IPs in last 60 seconds
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

        # Traffic Health
        active_alerts = Alert.objects.filter(resolved=False).count()
        violations_count = RateLimitViolation.objects.filter(timestamp__gte=window_60s).count()
        health = get_traffic_health(active_alerts, req_per_min, settings.request_threshold, violations_count)

        # Create snapshot in DB
        MonitoringSnapshot.objects.create(
            req_per_min=req_per_min,
            threshold=settings.request_threshold,
            health=json.dumps(health),
            top_ips_json=json.dumps(ip_rows)
        )

        # Prune old snapshots to prevent database bloat (keep last 300 snapshots)
        excess_snapshots = MonitoringSnapshot.objects.order_by('-timestamp')[300:]
        if excess_snapshots.exists():
            MonitoringSnapshot.objects.filter(pk__in=list(excess_snapshots.values_list('pk', flat=True))).delete()
