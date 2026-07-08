import logging
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from traffic.models import TrafficLog
from alerts.models import Alert, RateLimitViolation, SystemSettings, IPBlocklist

logger = logging.getLogger(__name__)


def get_severity(count, settings):
    """
    Assigns a severity level based on the number of requests in the time window,
    using the dynamically configured settings in SystemSettings.

    Why this matters in cybersecurity:
    - A small spike could be normal (caching, crawlers) → LOW
    - A moderate spike warrants investigation → MEDIUM
    - A large spike likely indicates an attack → HIGH
    - A massive spike is an active DDoS → CRITICAL

    Thresholds are set conservatively for a testing/lab environment.
    In production, these would be tuned to baseline traffic patterns.
    """
    if count >= settings.severity_critical_threshold:
        return Alert.SEVERITY_CRITICAL
    elif count >= settings.severity_high_threshold:
        return Alert.SEVERITY_HIGH
    elif count >= settings.severity_medium_threshold:
        return Alert.SEVERITY_MEDIUM
    else:
        return Alert.SEVERITY_LOW


def check_and_perform_auto_block(ip_address, count, settings):
    """
    Checks if automatic IP blocking is enabled and if the IP's request count
    exceeds the configured auto-block threshold. If so, adds the IP to IPBlocklist.
    """
    if settings.enable_auto_blocking and count >= settings.auto_block_threshold:
        if ip_address in ['127.0.0.1', '::1']:
            return  # Loopback bypass!
        from alerts.models import IPWhitelist
        if IPWhitelist.objects.filter(ip_address=ip_address).exists():
            return  # Whitelist bypass!

        if not IPBlocklist.objects.filter(ip_address=ip_address).exists():
            IPBlocklist.objects.create(
                ip_address=ip_address,
                reason=f"Automatically blocked: request count ({count}) exceeded threshold ({settings.auto_block_threshold}).",
                added_by=None
            )


def _active_alert_exists(ip_address, detection_type):
    """
    Deduplication guard used by detection engines.

    Returns True if there is already an unresolved Alert for the given IP
    and specific detection type.

    WHY THIS MATTERS:
    This prevents alert fatigue by ensuring only one active (unresolved) alert
    exists per IP and detection type at any given time.
    """
    return Alert.objects.filter(
        ip_address=ip_address,
        detection_type=detection_type,
        resolved=False,
    ).exists()


def detect_ddos(ip_address, settings=None):
    """
    Core DDoS detection engine using optimized threshold-based detection.

    Optimization:
    1. Request-IP-only processing: We only evaluate the IP of the incoming request
       to check if its count exceeds the spike threshold.
    2. Cached request counts: We store rolling window request counts in Django's
       cache system. Cache hits bypass DB count queries entirely.
    3. ORM optimization: Queries are indexed and limited to the targeted IP.
    """
    # Get dynamic settings from the database (or reuse pre-fetched settings)
    if settings is None:
        settings = SystemSettings.get_settings()
    time_window = settings.time_window_minutes
    threshold = settings.request_threshold

    # Calculate the start of our detection window
    window_start = timezone.now() - timedelta(minutes=time_window)

    cache_key = f"ddos_count:{ip_address}"
    count = cache.get(cache_key)

    if count is None:
        # Cache miss: query DB and cache it
        count = TrafficLog.objects.filter(
            timestamp__gte=window_start,
            ip_address=ip_address
        ).count()
        cache.set(cache_key, count, timeout=time_window * 60)
    else:
        # Cache hit: increment count and refresh cache
        count += 1
        cache.set(cache_key, count, timeout=time_window * 60)

    # Only process IPs that exceed the threshold
    if count > threshold:
        # Re-verify against database to get source-of-truth count (prevents race conditions)
        db_count = TrafficLog.objects.filter(
            timestamp__gte=window_start,
            ip_address=ip_address
        ).count()
        
        # Sync cache count
        cache.set(cache_key, db_count, timeout=time_window * 60)

        if db_count > threshold:
            # ── Automatic IP Blocking ────────────────────────────────────
            check_and_perform_auto_block(ip_address, db_count, settings)

            # ── Shared deduplication ─────────────────────────────────────
            if _active_alert_exists(ip_address, Alert.DETECTION_SPIKE):
                return

            # Determine severity based on request volume
            severity = get_severity(db_count, settings)

            # Create the alert record with detection_type = DETECTION_SPIKE
            Alert.objects.create(
                ip_address=ip_address,
                request_count=db_count,
                severity=severity,
                detection_type=Alert.DETECTION_SPIKE,
                message=(
                    f"Traffic Spike detected from IP {ip_address}. "
                    f"Requests in the last {time_window} minute(s): {db_count}. "
                    f"Threshold: {threshold}. Severity: {severity.upper()}"
                )
            )


def get_rate_limit_severity(count, threshold, settings):
    if count >= threshold * settings.rate_limit_critical_multiplier:
        return Alert.SEVERITY_CRITICAL
    if count >= threshold * settings.rate_limit_high_multiplier:
        return Alert.SEVERITY_HIGH
    return Alert.SEVERITY_MEDIUM


def detect_rate_limit_violation(ip_address, path, request_method, settings=None):
    """
    Detects whether an IP exceeded the configured request-rate limit.

    Optimization:
    1. Cached request counts: We query the Django cache system to retrieve the
       rolling rate-limit window request count.
    2. Fallback DB count: If cache misses, we perform a count query on the
       database and cache the result.
    """
    if settings is None:
        settings = SystemSettings.get_settings()
    threshold = settings.rate_limit_threshold
    time_window = settings.rate_limit_window_minutes

    window_start = timezone.now() - timedelta(minutes=time_window)

    cache_key = f"rate_limit_count:{ip_address}"
    count = cache.get(cache_key)

    if count is None:
        recent_logs = TrafficLog.objects.filter(
            timestamp__gte=window_start,
            ip_address=ip_address,
        )
        count = recent_logs.count()
        cache.set(cache_key, count, timeout=time_window * 60)
    else:
        count += 1
        cache.set(cache_key, count, timeout=time_window * 60)

    # ── Early exit: IP is within limits ────────────────────────────────────
    if count <= threshold:
        return None

    # ── Deduplication: prevent duplicate RateLimitViolation records ─────────
    duplicate_violation = RateLimitViolation.objects.filter(
        ip_address=ip_address,
        timestamp__gte=window_start,
    ).exists()
    if duplicate_violation:
        return None

    # Re-verify actual DB count to prevent false positives under extreme load
    db_count = TrafficLog.objects.filter(
        timestamp__gte=window_start,
        ip_address=ip_address,
    ).count()
    
    # Sync cache
    cache.set(cache_key, db_count, timeout=time_window * 60)

    if db_count <= threshold:
        return None

    # ── Automatic IP Blocking ────────────────────────────────────
    check_and_perform_auto_block(ip_address, db_count, settings)

    # ── Always create the RateLimitViolation record ─────────────────────────
    severity = get_rate_limit_severity(db_count, threshold, settings)
    message = (
        f"Rate-limit violation detected from IP {ip_address}. "
        f"Requests in the last {time_window} minute(s): {db_count}. "
        f"Allowed threshold: {threshold} requests/minute."
    )

    violation = RateLimitViolation.objects.create(
        ip_address=ip_address,
        request_count=db_count,
        threshold=threshold,
        window_minutes=time_window,
        path=path,
        request_method=request_method,
        message=message,
    )

    # ── Shared Alert Deduplication ──────────────────────────────────────────
    if not _active_alert_exists(ip_address, Alert.DETECTION_RATE_LIMIT):
        Alert.objects.create(
            ip_address=ip_address,
            request_count=db_count,
            severity=severity,
            detection_type=Alert.DETECTION_RATE_LIMIT,
            message=message,
        )

    return violation


def send_admin_email_alert(alert):
    """
    Sends an email alert notification to administrators for High and Critical threat levels.
    """
    if alert.severity not in [Alert.SEVERITY_HIGH, Alert.SEVERITY_CRITICAL]:
        return

    from django.core.mail import send_mail
    subject = f"NetWatch SECURITY ALERT: [{alert.severity.upper()}] Threat Detected!"
    message = (
        f"An incident of level {alert.severity.upper()} has been detected by NetWatch.\n\n"
        f"Details:\n"
        f"- Alert ID: #{alert.id}\n"
        f"- Detection Type: {alert.get_detection_type_display()}\n"
        f"- Attacker IP: {alert.ip_address}\n"
        f"- Volume / Counts: {alert.request_count}\n"
        f"- System Message: {alert.message}\n"
        f"- Timestamp: {alert.timestamp}\n\n"
        f"Please check the NetWatch security dashboard immediately to analyze logs and resolve this threat."
    )
    try:
        send_mail(
            subject,
            message,
            'security-alert@netwatch.local',
            ['admin@netwatch.local'],
            fail_silently=False
        )
        print(f"\n[EMAIL SIMULATOR - NetWatch Alert] Sent alert to admin@netwatch.local: {subject}\n")
    except Exception as e:
        logger.error(f"Failed to send security alert email: {e}")


def detect_security_events(ip_address, settings=None):
    """
    Analyzes SecurityEvent logs for a given IP in the sliding window.
    - Triggers 'failed_login' spike warning if failures >= 3.
    - Triggers 'brute_force' threat alert if failures >= 5.
    - Auto-blocks IP if auto-blocking settings are enabled.
    - Sends administrator alerts for critical severity incidents.
    """
    if settings is None:
        settings = SystemSettings.get_settings()

    time_window = settings.time_window_minutes
    window_start = timezone.now() - timedelta(minutes=time_window)

    from alerts.models import SecurityEvent, IPWhitelist, IPBlocklist

    # 1. Count failed login events for this IP
    failed_count = SecurityEvent.objects.filter(
        ip_address=ip_address,
        event_type='failed_login',
        timestamp__gte=window_start
    ).count()

    if failed_count <= 0:
        return

    # 2. Brute Force Attack Detection (failed logins >= 5)
    if failed_count >= 5:
        # Automatic IP Blocking
        if settings.enable_auto_blocking:
            if ip_address not in ['127.0.0.1', '::1'] and not IPWhitelist.objects.filter(ip_address=ip_address).exists():
                if not IPBlocklist.objects.filter(ip_address=ip_address).exists():
                    IPBlocklist.objects.create(
                        ip_address=ip_address,
                        reason=f"Automatically blocked: excessive login failures ({failed_count}) indicating active brute force.",
                        added_by=None
                    )

        # Create Brute Force alert if not active already
        if not _active_alert_exists(ip_address, Alert.DETECTION_BRUTE_FORCE):
            severity = Alert.SEVERITY_CRITICAL if failed_count >= 10 else Alert.SEVERITY_HIGH
            alert = Alert.objects.create(
                ip_address=ip_address,
                request_count=failed_count,
                severity=severity,
                detection_type=Alert.DETECTION_BRUTE_FORCE,
                message=(
                    f"Active Brute Force attack detected from IP {ip_address}. "
                    f"Attempts in last {time_window} minute(s): {failed_count}. "
                    f"Threshold: 5. Severity: {severity.upper()}"
                )
            )
            send_admin_email_alert(alert)

    # 3. Failed Login Spike Detection (failed logins >= 3)
    elif failed_count >= 3:
        if not _active_alert_exists(ip_address, Alert.DETECTION_FAILED_LOGIN):
            alert = Alert.objects.create(
                ip_address=ip_address,
                request_count=failed_count,
                severity=Alert.SEVERITY_MEDIUM,
                detection_type=Alert.DETECTION_FAILED_LOGIN,
                message=(
                    f"Failed Login Spike detected from IP {ip_address}. "
                    f"Failed logins in last {time_window} minute(s): {failed_count}. "
                    f"Threshold: 3. Severity: MEDIUM"
                )
            )
            send_admin_email_alert(alert)