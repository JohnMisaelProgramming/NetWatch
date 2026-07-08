import json
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.models import User

from traffic.models import TrafficLog
from alerts.models import Alert, SystemSettings, RateLimitViolation, IPBlocklist, IPWhitelist, MonitoringSnapshot, AuditLog, AlertNote, SimulationRun


class Command(BaseCommand):
    help = "Clears all monitor data and populates clean, realistic seed data (at least 5 records per table) for testing."

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Clearing existing data (except accounts)..."))
        
        # ── 1. Clear tables ────────────────────────────────────────────────
        TrafficLog.objects.all().delete()
        Alert.objects.all().delete()
        RateLimitViolation.objects.all().delete()
        IPBlocklist.objects.all().delete()
        IPWhitelist.objects.all().delete()
        MonitoringSnapshot.objects.all().delete()
        AuditLog.objects.all().delete()
        AlertNote.objects.all().delete()
        SimulationRun.objects.all().delete()

        # Reset Settings
        SystemSettings.objects.all().delete()
        settings = SystemSettings.get_settings()
        settings.enable_auto_blocking = True
        settings.save()

        # Find or fallback admin & analyst users
        admin_user = User.objects.filter(username='admin').first()
        if not admin_user:
            admin_user = User.objects.filter(is_superuser=True).first()
        if not admin_user:
            admin_user = User.objects.create_superuser('admin', 'admin@netwatch.local', 'NetWatch123!')
            from accounts.models import Profile
            profile, _ = Profile.objects.get_or_create(user=admin_user)
            profile.role = 'admin'
            profile.save()

        analyst_user = User.objects.filter(username='analyst').first()
        if not analyst_user:
            analyst_user = User.objects.create_user('analyst', 'analyst@netwatch.local', 'NetWatch123!')
            from accounts.models import Profile
            profile, _ = Profile.objects.get_or_create(user=analyst_user)
            profile.role = 'analyst'
            profile.save()

        now = timezone.now()

        # ── 2. Seed IPBlocklist (5 entries) ────────────────────────────────
        self.stdout.write("Seeding IP Blocklist...")
        blocked_ips = [
            ("198.51.100.42", "Repeated DDoS Spike attack detected on checkout page", now - timedelta(hours=2)),
            ("203.0.113.110", "API Rate Limit Abuser (bot scanning endpoints)", now - timedelta(hours=5)),
            ("192.0.2.75", "Credential stuffing brute-force attempts on login screen", now - timedelta(hours=12)),
            ("45.223.10.89", "SQL Injection vulnerability scanner detected", now - timedelta(days=1)),
            ("185.190.140.5", "Persistent request-flooding from non-residential network", now - timedelta(days=2)),
        ]
        for ip, reason, added_at in blocked_ips:
            IPBlocklist.objects.create(
                ip_address=ip,
                reason=reason,
                added_by=admin_user,
                added_at=added_at
            )

        # ── 3. Seed IPWhitelist (5 entries) ────────────────────────────────
        self.stdout.write("Seeding IP Whitelist...")
        whitelist_ips = [
            ("192.168.1.1", "Primary Network Default Gateway", now - timedelta(days=5)),
            ("10.0.0.15", "Application Internal Load Balancer Node", now - timedelta(days=5)),
            ("192.168.5.50", "Lead Security Analyst Workstation IP", now - timedelta(days=4)),
            ("127.0.0.1", "Local Host Loopback Address (System Safety Whitelist)", now - timedelta(days=10)),
            ("8.8.8.8", "Google Public DNS Server (external health checker source)", now - timedelta(days=1)),
        ]
        for ip, reason, added_at in whitelist_ips:
            IPWhitelist.objects.create(
                ip_address=ip,
                reason=reason,
                added_by=admin_user,
                added_at=added_at
            )

        # ── 4. Seed TrafficLog (15 entries) ────────────────────────────────
        self.stdout.write("Seeding Traffic Logs...")
        traffic_logs = [
            # Normal traffic (safe IP)
            ("192.168.5.50", "/products/", "GET", now - timedelta(minutes=1)),
            ("192.168.5.50", "/cart/", "GET", now - timedelta(minutes=2)),
            ("192.168.5.50", "/checkout/", "POST", now - timedelta(minutes=3)),
            # Attack traffic (blocked or high-rate IPs)
            ("198.51.100.42", "/api/checkout/", "POST", now - timedelta(minutes=5)),
            ("198.51.100.42", "/api/checkout/", "POST", now - timedelta(minutes=6)),
            ("203.0.113.110", "/api/v1/products/", "GET", now - timedelta(minutes=10)),
            ("203.0.113.110", "/api/v1/products/", "GET", now - timedelta(minutes=11)),
            ("192.0.2.75", "/login/", "POST", now - timedelta(minutes=15)),
            ("192.0.2.75", "/login/", "POST", now - timedelta(minutes=16)),
            ("45.223.10.89", "/products/?id=1%20OR%201=1", "GET", now - timedelta(hours=1)),
            ("45.223.10.89", "/admin/login/", "GET", now - timedelta(hours=1, minutes=5)),
            ("185.190.140.5", "/search/?q=shoes", "GET", now - timedelta(hours=2)),
            # Additional clean traffic logs
            ("8.8.8.8", "/health/", "GET", now - timedelta(minutes=12)),
            ("10.0.0.15", "/api/status/", "GET", now - timedelta(minutes=14)),
            ("192.168.5.50", "/", "GET", now - timedelta(minutes=20)),
        ]
        for ip, url, method, ts in traffic_logs:
            # We override auto_now_add using bulk_create or direct save modification
            log = TrafficLog(ip_address=ip, url_accessed=url, request_method=method)
            log.save()
            # Force the timestamp to be custom for realistic timeline
            TrafficLog.objects.filter(pk=log.pk).update(timestamp=ts)

        # ── 5. Seed Alerts (5 entries) ─────────────────────────────────────
        self.stdout.write("Seeding Alerts...")
        alerts = [
            # ip, request_count, message, resolved, severity, detection_type, resolved_by, resolved_at, timestamp
            ("198.51.100.42", 120, "DDoS attack traffic spike: 120 reqs/min exceeds threshold (50)", False, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, None, None, now - timedelta(hours=1)),
            ("203.0.113.110", 45, "Rate limit violation: IP exceeded API call limit of 30 reqs/min", False, Alert.SEVERITY_HIGH, Alert.DETECTION_RATE_LIMIT, None, None, now - timedelta(hours=2)),
            ("192.0.2.75", 65, "Brute force pattern detected on login endpoints (65 attempts/min)", True, Alert.SEVERITY_MEDIUM, Alert.DETECTION_SPIKE, analyst_user, now - timedelta(hours=5), now - timedelta(hours=6)),
            ("45.223.10.89", 110, "Critical HTTP scanner traffic spike (110 attempts/min)", True, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, admin_user, now - timedelta(hours=8), now - timedelta(hours=10)),
            ("185.190.140.5", 15, "Manual alert: Abnormal user-agent header patterns detected from this IP", False, Alert.SEVERITY_LOW, Alert.DETECTION_MANUAL, None, None, now - timedelta(days=1)),
        ]
        
        alerts_instances = []
        for ip, count, msg, res, sev, det, res_by, res_at, ts in alerts:
            alt = Alert.objects.create(
                ip_address=ip,
                request_count=count,
                message=msg,
                resolved=res,
                severity=sev,
                detection_type=det,
                resolved_by=res_by,
                resolved_at=res_at,
            )
            Alert.objects.filter(pk=alt.pk).update(timestamp=ts)
            alerts_instances.append(alt)

        # ── 6. Seed AlertNotes (5 entries) ─────────────────────────────────
        self.stdout.write("Seeding Alert Notes...")
        notes = [
            (alerts_instances[0], "High volume of traffic targeting checkout API. Confirming with ShopSafe backend logs."),
            (alerts_instances[0], "Confirmed. This is malicious traffic from a proxy network. Moving to block."),
            (alerts_instances[1], "IP is scanning v1 products list. No human browser signature found."),
            (alerts_instances[2], "Brute force attack stopped after 65 attempts. Account locked. Marking resolved."),
            (alerts_instances[3], "Vulnerability scanner blocked at network layer. Marking resolved."),
        ]
        for alert, content in notes:
            AlertNote.objects.create(
                alert=alert,
                author=analyst_user,
                content=content,
                created_at=alert.timestamp + timedelta(minutes=15)
            )

        # ── 7. Seed RateLimitViolations (5 entries) ───────────────────────
        self.stdout.write("Seeding Rate Limit Violations...")
        violations = [
            ("203.0.113.110", 45, 30, 1, "/api/v1/products/", "GET", "Client exceeded API request rate of 30 req/min", now - timedelta(hours=2)),
            ("198.51.100.42", 52, 30, 1, "/api/checkout/", "POST", "Rate limit violated on checkout gateway", now - timedelta(hours=3)),
            ("192.0.2.75", 35, 30, 1, "/login/", "POST", "Excessive login attempts detected", now - timedelta(hours=6)),
            ("185.190.140.5", 32, 30, 1, "/search/", "GET", "Search crawler rate-limit limit hit", now - timedelta(days=1)),
            ("45.223.10.89", 80, 30, 1, "/admin/login/", "GET", "Automated system scraper violated rate limit", now - timedelta(days=1, hours=2)),
        ]
        for ip, count, th, win, path, method, msg, ts in violations:
            v = RateLimitViolation.objects.create(
                ip_address=ip,
                request_count=count,
                threshold=th,
                window_minutes=win,
                path=path,
                request_method=method,
                message=msg
            )
            RateLimitViolation.objects.filter(pk=v.pk).update(timestamp=ts)

        # ── 8. Seed MonitoringSnapshots (5 entries) ────────────────────────
        self.stdout.write("Seeding Monitoring Snapshots...")
        for i in range(5):
            ts = now - timedelta(minutes=5 * i)
            # Create mock health dictionary matching the schema of get_traffic_health
            from dashboard.views import get_traffic_health
            active_alerts = 2 if i == 2 else 0
            req_per_min = 15 + i * 8
            threshold = 50
            violations_count = 3 if i == 2 else 0
            health = get_traffic_health(active_alerts, req_per_min, threshold, violations_count)
            # Create mock top IPs list
            top_ips = [
                {'ip': '192.168.5.50', 'count': 10, 'pct': 100, 'pct_total': 50, 'status': 'normal', 'risk': 'low'},
                {'ip': '198.51.100.42', 'count': 8, 'pct': 80, 'pct_total': 40, 'status': 'blocked', 'risk': 'critical'},
            ]
            snap = MonitoringSnapshot.objects.create(
                req_per_min=15 + i * 8,
                threshold=50,
                health=json.dumps(health),
                top_ips_json=json.dumps(top_ips)
            )
            MonitoringSnapshot.objects.filter(pk=snap.pk).update(timestamp=ts)

        # ── 9. Seed AuditLogs (5 entries) ──────────────────────────────────
        self.stdout.write("Seeding Audit Logs...")
        audit_logs = [
            ("resolve_alert", "Alert #3 — IP 192.0.2.75", "Resolved brute force alert after password lockout", analyst_user, now - timedelta(hours=5)),
            ("resolve_alert", "Alert #4 — IP 45.223.10.89", "Resolved vulnerability scanner alert", admin_user, now - timedelta(hours=8)),
            ("block_ip", "198.51.100.42", "Blocked attacker IP after massive checkout DDoS spike", admin_user, now - timedelta(hours=2)),
            ("block_ip", "203.0.113.110", "Blocked API scraping bot", analyst_user, now - timedelta(hours=5)),
            ("update_settings", "System Settings", "Updated Request Threshold to 50 and Auto-blocking to Enabled", admin_user, now - timedelta(hours=10)),
        ]
        for action, target, details, u, ts in audit_logs:
            log = AuditLog.objects.create(
                user=u,
                action=action,
                target=target,
                details=details,
            )
            AuditLog.objects.filter(pk=log.pk).update(timestamp=ts)

        # ── 10. Seed SimulationRuns (5 entries) ────────────────────────────
        self.stdout.write("Seeding Simulation Lab Runs...")
        sim_runs = [
            ("ddos", "/api/checkout/", 500, 10, 8, "completed", 500, 240, now - timedelta(hours=1)),
            ("rate_limit", "/api/v1/products/", 200, 50, 2, "completed", 200, 120, now - timedelta(hours=4)),
            ("spike", "/search/", 150, 100, 1, "completed", 150, 0, now - timedelta(hours=6)),
            ("normal", "/", 100, 200, 1, "completed", 100, 0, now - timedelta(hours=12)),
            ("ddos", "/login/", 1000, 10, 5, "stopped", 450, 120, now - timedelta(days=1)),
        ]
        for attack, target, num, delay, ips, status, sent, blocked, ts in sim_runs:
            s = SimulationRun.objects.create(
                attack_type=attack,
                target_endpoint=target,
                num_requests=num,
                delay_ms=delay,
                simulated_ips_count=ips,
                status=status,
                requests_sent=sent,
                requests_blocked=blocked,
                ended_at=ts + timedelta(minutes=5)
            )
            SimulationRun.objects.filter(pk=s.pk).update(started_at=ts)

        self.stdout.write(self.style.SUCCESS("[OK] Data seeded successfully! NetWatch is now fully populated."))
