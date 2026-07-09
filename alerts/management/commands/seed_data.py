import json
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.models import User

from traffic.models import TrafficLog
from alerts.models import Alert, SystemSettings, RateLimitViolation, IPBlocklist, IPWhitelist, MonitoringSnapshot, AuditLog, AlertNote, SimulationRun, SecurityEvent


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
        SecurityEvent.objects.all().delete()

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
        blocklist_instances = []
        for ip, reason, added_at in blocked_ips:
            block = IPBlocklist(
                ip_address=ip,
                reason=reason,
                added_by=admin_user,
            )
            blocklist_instances.append((block, added_at))
        
        created_blocks = IPBlocklist.objects.bulk_create([b[0] for b in blocklist_instances])
        for i, block in enumerate(created_blocks):
            block.added_at = blocklist_instances[i][1]
        IPBlocklist.objects.bulk_update(created_blocks, ['added_at'])

        # ── 3. Seed IPWhitelist (5 entries) ────────────────────────────────
        self.stdout.write("Seeding IP Whitelist...")
        whitelist_ips = [
            ("192.168.1.1", "Primary Network Default Gateway", now - timedelta(days=5)),
            ("10.0.0.15", "Application Internal Load Balancer Node", now - timedelta(days=5)),
            ("192.168.5.50", "Lead Security Analyst Workstation IP", now - timedelta(days=4)),
            ("127.0.0.1", "Local Host Loopback Address (System Safety Whitelist)", now - timedelta(days=10)),
            ("8.8.8.8", "Google Public DNS Server (external health checker source)", now - timedelta(days=1)),
        ]
        whitelist_instances = []
        for ip, reason, added_at in whitelist_ips:
            wl = IPWhitelist(
                ip_address=ip,
                reason=reason,
                added_by=admin_user,
            )
            whitelist_instances.append((wl, added_at))
        
        created_whitelists = IPWhitelist.objects.bulk_create([w[0] for w in whitelist_instances])
        for i, wl in enumerate(created_whitelists):
            wl.added_at = whitelist_instances[i][1]
        IPWhitelist.objects.bulk_update(created_whitelists, ['added_at'])

        # ── 4. Seed TrafficLog (30 days of data) ───────────────────────────
        self.stdout.write("Seeding Traffic Logs (30 days of data)...")
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
        
        import random
        import math
        
        safe_ips = ["192.168.5.50", "192.168.1.100", "8.8.8.8", "10.0.0.15", "172.16.0.23", "204.79.197.200"]
        urls = ["/", "/products/", "/cart/", "/checkout/", "/api/v1/products/", "/search/"]
        methods = ["GET", "POST"]
        
        seeded_logs = []
        
        # Add original logs first
        for ip, url, method, ts in traffic_logs:
            seeded_logs.append((TrafficLog(ip_address=ip, url_accessed=url, request_method=method), ts))
            
        # Add 30 days of historical logs
        for day in range(30, 0, -1):
            day_date = now - timedelta(days=day)
            
            # Daily traffic volume (sine wave + random noise)
            wave = math.sin(day * (math.pi / 3.5))  # weekly cycle
            num_requests = int(60 + wave * 25 + random.randint(-8, 8))
            
            for _ in range(num_requests):
                ip = random.choice(safe_ips)
                url = random.choice(urls)
                method = "POST" if url == "/checkout/" or url == "/login/" else random.choice(methods)
                # Random time of day
                hour = random.choices(
                    population=list(range(24)),
                    weights=[1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 10, 10, 10, 10, 10, 10, 10, 9, 8, 6, 4, 3, 2, 1],
                    k=1
                )[0]
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts = day_date.replace(hour=hour, minute=minute, second=second)
                
                seeded_logs.append((TrafficLog(ip_address=ip, url_accessed=url, request_method=method), ts))
                
            # Inject attack traffic spikes on specific days
            # Day 28: DDoS spike from 198.51.100.42
            if day == 28:
                attack_ts_base = day_date.replace(hour=14, minute=30)
                for i in range(120):
                    seeded_logs.append((TrafficLog(
                        ip_address="198.51.100.42",
                        url_accessed="/api/checkout/",
                        request_method="POST"
                    ), attack_ts_base + timedelta(seconds=i * 2)))
                    
            # Day 21: Rate limit violation from 203.0.113.110
            elif day == 21:
                attack_ts_base = day_date.replace(hour=10, minute=15)
                for i in range(45):
                    seeded_logs.append((TrafficLog(
                        ip_address="203.0.113.110",
                        url_accessed="/api/v1/products/",
                        request_method="GET"
                    ), attack_ts_base + timedelta(seconds=i)))
                    
            # Day 14: Brute force attempts from 192.0.2.75
            elif day == 14:
                attack_ts_base = day_date.replace(hour=22, minute=5)
                for i in range(65):
                    seeded_logs.append((TrafficLog(
                        ip_address="192.0.2.75",
                        url_accessed="/login/",
                        request_method="POST"
                    ), attack_ts_base + timedelta(seconds=i)))
                    
            # Day 7: Critical HTTP scanner spike from 45.223.10.89
            elif day == 7:
                attack_ts_base = day_date.replace(hour=8, minute=45)
                for i in range(110):
                    seeded_logs.append((TrafficLog(
                        ip_address="45.223.10.89",
                        url_accessed="/admin/login/",
                        request_method="GET"
                    ), attack_ts_base + timedelta(seconds=i // 2)))

        # Bulk create for efficiency
        created_traffic = TrafficLog.objects.bulk_create([log[0] for log in seeded_logs])
        chunk_size = 400
        for i in range(0, len(created_traffic), chunk_size):
            chunk = created_traffic[i:i+chunk_size]
            for j, log in enumerate(chunk):
                log.timestamp = seeded_logs[i+j][1]
            TrafficLog.objects.bulk_update(chunk, ['timestamp'])

        # ── 5. Seed Alerts (30 days of data) ───────────────────────────────
        self.stdout.write("Seeding Alerts (30 days)...")
        alerts_data = [
            # Original ones
            ("198.51.100.42", 120, "DDoS attack traffic spike: 120 reqs/min exceeds threshold (50)", False, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, None, None, now - timedelta(hours=1)),
            ("203.0.113.110", 45, "Rate limit violation: IP exceeded API call limit of 30 reqs/min", False, Alert.SEVERITY_HIGH, Alert.DETECTION_RATE_LIMIT, None, None, now - timedelta(hours=2)),
            ("192.0.2.75", 65, "Brute force pattern detected on login endpoints (65 attempts/min)", True, Alert.SEVERITY_MEDIUM, Alert.DETECTION_SPIKE, analyst_user, now - timedelta(hours=5), now - timedelta(hours=6)),
            ("45.223.10.89", 110, "Critical HTTP scanner traffic spike (110 attempts/min)", True, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, admin_user, now - timedelta(hours=8), now - timedelta(hours=10)),
            ("185.190.140.5", 15, "Manual alert: Abnormal user-agent header patterns detected from this IP", False, Alert.SEVERITY_LOW, Alert.DETECTION_MANUAL, None, None, now - timedelta(days=1)),
            
            # Historical ones
            ("198.51.100.42", 120, "DDoS attack traffic spike: 120 reqs/min exceeds threshold (50)", True, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, admin_user, now - timedelta(days=28, hours=2), now - timedelta(days=28, hours=3)),
            ("203.0.113.110", 45, "Rate limit violation: IP exceeded API call limit of 30 reqs/min", True, Alert.SEVERITY_HIGH, Alert.DETECTION_RATE_LIMIT, analyst_user, now - timedelta(days=21, hours=1), now - timedelta(days=21, hours=2)),
            ("192.0.2.75", 65, "Brute force pattern detected on login endpoints (65 attempts/min)", True, Alert.SEVERITY_MEDIUM, Alert.DETECTION_SPIKE, analyst_user, now - timedelta(days=14, hours=3), now - timedelta(days=14, hours=4)),
            ("45.223.10.89", 110, "Critical HTTP scanner traffic spike (110 attempts/min)", True, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, admin_user, now - timedelta(days=7, hours=4), now - timedelta(days=7, hours=5)),
            ("185.190.140.5", 25, "Manual alert: Abnormal user-agent header patterns detected from this IP", True, Alert.SEVERITY_LOW, Alert.DETECTION_MANUAL, analyst_user, now - timedelta(days=2, hours=1), now - timedelta(days=2, hours=2)),
            
            # Some other random events
            ("198.51.100.12", 80, "Traffic spike: 80 reqs/min from unknown host", True, Alert.SEVERITY_MEDIUM, Alert.DETECTION_SPIKE, analyst_user, now - timedelta(days=25), now - timedelta(days=25, hours=1)),
            ("203.0.113.15", 35, "Rate limit violation on static resource folder", True, Alert.SEVERITY_LOW, Alert.DETECTION_RATE_LIMIT, analyst_user, now - timedelta(days=18), now - timedelta(days=18, hours=1)),
            ("192.0.2.99", 55, "Failed Login Spike: 55 failed logins in 5 minutes", True, Alert.SEVERITY_MEDIUM, Alert.DETECTION_FAILED_LOGIN, analyst_user, now - timedelta(days=12), now - timedelta(days=12, hours=1)),
            ("45.223.10.100", 130, "Critical HTTP scanner traffic spike (130 attempts/min)", True, Alert.SEVERITY_CRITICAL, Alert.DETECTION_SPIKE, admin_user, now - timedelta(days=5), now - timedelta(days=5, hours=1)),
        ]
        
        alerts_instances = []
        alert_creation_list = []
        for ip, count, msg, res, sev, det, res_by, res_at, ts in alerts_data:
            alt = Alert(
                ip_address=ip,
                request_count=count,
                message=msg,
                resolved=res,
                severity=sev,
                detection_type=det,
                resolved_by=res_by,
                resolved_at=res_at,
            )
            alert_creation_list.append((alt, ts))
            
        created_alerts = Alert.objects.bulk_create([x[0] for x in alert_creation_list])
        for i, alt in enumerate(created_alerts):
            alt.timestamp = alert_creation_list[i][1]
            alerts_instances.append(alt)
        Alert.objects.bulk_update(created_alerts, ['timestamp'])

        # ── 6. Seed AlertNotes (30 days of data) ───────────────────────────
        self.stdout.write("Seeding Alert Notes...")
        notes_data = [
            (alerts_instances[0], "High volume of traffic targeting checkout API. Confirming with ShopSafe backend logs."),
            (alerts_instances[0], "Confirmed. This is malicious traffic from a proxy network. Moving to block."),
            (alerts_instances[1], "IP is scanning v1 products list. No human browser signature found."),
            (alerts_instances[2], "Brute force attack stopped after 65 attempts. Account locked. Marking resolved."),
            (alerts_instances[3], "Vulnerability scanner blocked at network layer. Marking resolved."),
            
            # Historical notes
            (alerts_instances[5], "DDoS attack detected on checkout page. Auto-block triggered. Verified with backend logs."),
            (alerts_instances[6], "Rate limit violation confirmed. Access keys rotated for security."),
            (alerts_instances[7], "IP locked out after brute force pattern detected. Alert marked resolved."),
            (alerts_instances[8], "Vulnerability scanner blocked by network router. Alert resolved."),
        ]
        
        note_creation_list = []
        for alert, content in notes_data:
            note = AlertNote(
                alert=alert,
                author=analyst_user,
                content=content,
            )
            ts = alert.timestamp + timedelta(minutes=15)
            note_creation_list.append((note, ts))
            
        created_notes = AlertNote.objects.bulk_create([x[0] for x in note_creation_list])
        for i, note in enumerate(created_notes):
            note.created_at = note_creation_list[i][1]
        AlertNote.objects.bulk_update(created_notes, ['created_at'])

        # ── 7. Seed RateLimitViolations (30 days of data) ──────────────────
        self.stdout.write("Seeding Rate Limit Violations...")
        violations = [
            # Original ones
            ("203.0.113.110", 45, 30, 1, "/api/v1/products/", "GET", "Client exceeded API request rate of 30 req/min", now - timedelta(hours=2)),
            ("198.51.100.42", 52, 30, 1, "/api/checkout/", "POST", "Rate limit violated on checkout gateway", now - timedelta(hours=3)),
            ("192.0.2.75", 35, 30, 1, "/login/", "POST", "Excessive login attempts detected", now - timedelta(hours=6)),
            ("185.190.140.5", 32, 30, 1, "/search/", "GET", "Search crawler rate-limit limit hit", now - timedelta(days=1)),
            ("45.223.10.89", 80, 30, 1, "/admin/login/", "GET", "Automated system scraper violated rate limit", now - timedelta(days=1, hours=2)),
            
            # Historical ones
            ("203.0.113.110", 45, 30, 1, "/api/v1/products/", "GET", "Client exceeded API request rate of 30 req/min", now - timedelta(days=21, hours=2)),
            ("198.51.100.42", 52, 30, 1, "/api/checkout/", "POST", "Rate limit violated on checkout gateway", now - timedelta(days=28, hours=3)),
            ("192.0.2.75", 35, 30, 1, "/login/", "POST", "Excessive login attempts detected", now - timedelta(days=14, hours=4)),
            ("185.190.140.5", 32, 30, 1, "/search/", "GET", "Search crawler rate-limit limit hit", now - timedelta(days=2, hours=2)),
        ]
        violation_creation_list = []
        for ip, count, th, win, path, method, msg, ts in violations:
            v = RateLimitViolation(
                ip_address=ip,
                request_count=count,
                threshold=th,
                window_minutes=win,
                path=path,
                request_method=method,
                message=msg
            )
            violation_creation_list.append((v, ts))
            
        created_violations = RateLimitViolation.objects.bulk_create([x[0] for x in violation_creation_list])
        for i, v in enumerate(created_violations):
            v.timestamp = violation_creation_list[i][1]
        RateLimitViolation.objects.bulk_update(created_violations, ['timestamp'])

        # ── 8. Seed MonitoringSnapshots (5 entries) ────────────────────────
        self.stdout.write("Seeding Monitoring Snapshots...")
        for i in range(5):
            ts = now - timedelta(minutes=5 * i)
            from dashboard.views import get_traffic_health
            active_alerts = 2 if i == 2 else 0
            req_per_min = 15 + i * 8
            threshold = 50
            violations_count = 3 if i == 2 else 0
            health = get_traffic_health(active_alerts, req_per_min, threshold, violations_count)
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

        # ── 9. Seed AuditLogs (30 days of data) ────────────────────────────
        self.stdout.write("Seeding Audit Logs...")
        audit_logs = [
            ("resolve_alert", "Alert #3 — IP 192.0.2.75", "Resolved brute force alert after password lockout", analyst_user, now - timedelta(hours=5)),
            ("resolve_alert", "Alert #4 — IP 45.223.10.89", "Resolved vulnerability scanner alert", admin_user, now - timedelta(hours=8)),
            ("block_ip", "198.51.100.42", "Blocked attacker IP after massive checkout DDoS spike", admin_user, now - timedelta(hours=2)),
            ("block_ip", "203.0.113.110", "Blocked API scraping bot", analyst_user, now - timedelta(hours=5)),
            ("update_settings", "System Settings", "Updated Request Threshold to 50 and Auto-blocking to Enabled", admin_user, now - timedelta(hours=10)),
            
            # Historical ones
            ("resolve_alert", "Alert #6 — IP 198.51.100.42", "Resolved checkout DDoS spike alert", admin_user, now - timedelta(days=28, hours=2)),
            ("resolve_alert", "Alert #7 — IP 203.0.113.110", "Resolved API rate limit violation alert", analyst_user, now - timedelta(days=21, hours=1)),
            ("resolve_alert", "Alert #8 — IP 192.0.2.75", "Resolved login brute force alert", analyst_user, now - timedelta(days=14, hours=3)),
            ("resolve_alert", "Alert #9 — IP 45.223.10.89", "Resolved HTTP scanner alert", admin_user, now - timedelta(days=7, hours=4)),
            ("block_ip", "198.51.100.42", "Blocked attacker IP after Day 28 DDoS spike", admin_user, now - timedelta(days=28, hours=2)),
            ("block_ip", "203.0.113.110", "Blocked API scraping bot after Day 21 violation", analyst_user, now - timedelta(days=21, hours=1)),
        ]
        audit_creation_list = []
        for action, target, details, u, ts in audit_logs:
            log = AuditLog(
                user=u,
                action=action,
                target=target,
                details=details,
            )
            audit_creation_list.append((log, ts))
            
        created_audit = AuditLog.objects.bulk_create([x[0] for x in audit_creation_list])
        for i, log in enumerate(created_audit):
            log.timestamp = audit_creation_list[i][1]
        AuditLog.objects.bulk_update(created_audit, ['timestamp'])

        # ── 10. Seed SimulationRuns (30 days of data) ──────────────────────
        self.stdout.write("Seeding Simulation Lab Runs...")
        sim_runs = [
            ("ddos", "/api/checkout/", 500, 10, 8, "completed", 500, 240, now - timedelta(hours=1)),
            ("rate_limit", "/api/v1/products/", 200, 50, 2, "completed", 200, 120, now - timedelta(hours=4)),
            ("spike", "/search/", 150, 100, 1, "completed", 150, 0, now - timedelta(hours=6)),
            ("normal", "/", 100, 200, 1, "completed", 100, 0, now - timedelta(hours=12)),
            ("ddos", "/login/", 1000, 10, 5, "stopped", 450, 120, now - timedelta(days=1)),
            
            # Historical ones
            ("ddos", "/api/checkout/", 500, 10, 8, "completed", 500, 240, now - timedelta(days=28)),
            ("rate_limit", "/api/v1/products/", 200, 50, 2, "completed", 200, 120, now - timedelta(days=21)),
            ("spike", "/login/", 150, 100, 1, "completed", 150, 0, now - timedelta(days=14)),
            ("normal", "/", 100, 200, 1, "completed", 100, 0, now - timedelta(days=10)),
        ]
        sim_creation_list = []
        for attack, target, num, delay, ips, status, sent, blocked, ts in sim_runs:
            s = SimulationRun(
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
            sim_creation_list.append((s, ts))
            
        created_sim = SimulationRun.objects.bulk_create([x[0] for x in sim_creation_list])
        for i, s in enumerate(created_sim):
            s.started_at = sim_creation_list[i][1]
        SimulationRun.objects.bulk_update(created_sim, ['started_at'])

        # ── 11. Seed SecurityEvents (30 days of data) ──────────────────────
        self.stdout.write("Seeding Security Events...")
        security_events = [
            ("192.0.2.75", "failed_login", "admin", "Failed password attempt", "Mozilla/5.0", "shopsafe", now - timedelta(days=14, hours=3)),
            ("192.0.2.75", "failed_login", "admin", "Failed password attempt", "Mozilla/5.0", "shopsafe", now - timedelta(days=14, hours=3, minutes=1)),
            ("192.0.2.75", "failed_login", "admin", "Failed password attempt", "Mozilla/5.0", "shopsafe", now - timedelta(days=14, hours=3, minutes=2)),
            ("192.0.2.75", "lockout", "admin", "Account locked due to 3 failed attempts", "Mozilla/5.0", "shopsafe", now - timedelta(days=14, hours=3, minutes=2, seconds=10)),
            
            ("192.168.5.50", "successful_login", "analyst", "Successful login via local workstation", "Mozilla/5.0", "netwatch", now - timedelta(days=5)),
            ("192.168.5.50", "logout", "analyst", "Clean logout session ended", "Mozilla/5.0", "netwatch", now - timedelta(days=5, hours=4)),
            
            ("10.0.0.15", "performance_telemetry", None, "CPU usage: 12%, Memory: 42%", "HealthCheck/1.0", "shopsafe", now - timedelta(minutes=5)),
            ("198.51.100.42", "blocked", None, "Traffic blocked dynamically: DDoS Spike rule triggered", "cURL/7.68.0", "shopsafe", now - timedelta(hours=2)),
            ("203.0.113.110", "blocked", None, "Traffic blocked dynamically: Rate Limit rule triggered", "Python-requests/2.25.1", "shopsafe", now - timedelta(hours=5)),
            
            ("192.168.1.100", "successful_login", "john_doe", "User login successful from main LAN", "Mozilla/5.0", "shopsafe", now - timedelta(days=10)),
            ("192.168.1.100", "otp_verification", "john_doe", "OTP code sent and verified", "Mozilla/5.0", "shopsafe", now - timedelta(days=10, minutes=2)),
            ("192.168.1.100", "logout", "john_doe", "User logout successful", "Mozilla/5.0", "shopsafe", now - timedelta(days=10, hours=1)),
        ]
        se_creation_list = []
        for ip, et, user, det, ua, src, ts in security_events:
            se = SecurityEvent(
                ip_address=ip,
                event_type=et,
                username=user,
                details=det,
                user_agent=ua,
                source=src
            )
            se_creation_list.append((se, ts))
            
        created_se = SecurityEvent.objects.bulk_create([x[0] for x in se_creation_list])
        for i, se in enumerate(created_se):
            se.timestamp = se_creation_list[i][1]
        SecurityEvent.objects.bulk_update(created_se, ['timestamp'])

        self.stdout.write(self.style.SUCCESS("[OK] Data seeded successfully! NetWatch is now fully populated."))
