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

        # ── 1c. Run Security Event analysis for brute force & failed login detection ──
        from alerts.models import SecurityEvent
        from alerts.detector import detect_security_events
        active_event_ips = list(
            SecurityEvent.objects
            .filter(timestamp__gte=window_start)
            .values_list('ip_address', flat=True)
            .distinct()
        )
        for ip in active_event_ips:
            detect_security_events(ip, settings=settings)

        # ── 2. Pre-calculate dashboard statistics and write to snapshot ──
        # Uses shared utility to avoid code duplication (DRY)
        from alerts.utils import compute_ip_rows
        ip_rows, req_per_min = compute_ip_rows(window_seconds=60)

        # Traffic Health
        window_60s = now - timedelta(seconds=60)
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

        # Prune old snapshots using timestamp (faster than subquery on SQLite)
        # Keep snapshots from the last 30 minutes only
        cutoff = now - timedelta(minutes=30)
        MonitoringSnapshot.objects.filter(timestamp__lt=cutoff).delete()

        # ── 3. Data retention cleanup ──────────────────────────────────────
        # Auto-delete traffic logs older than the configured retention period
        if settings.data_retention_days and settings.data_retention_days > 0:
            retention_cutoff = now - timedelta(days=settings.data_retention_days)
            deleted_count, _ = TrafficLog.objects.filter(timestamp__lt=retention_cutoff).delete()
            if deleted_count > 0:
                self.stdout.write(
                    f"  Data retention: Deleted {deleted_count} traffic logs older than {settings.data_retention_days} days"
                )

