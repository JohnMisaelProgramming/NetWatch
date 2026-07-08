from django.db import models
from django.conf import settings


class Alert(models.Model):

    # ─── Severity Level Choices ────────────────────────────────────────────
    # These represent how dangerous a detected alert is.
    # LOW:      Minor anomaly, worth watching but not urgent.
    # MEDIUM:   Moderate threat, investigate soon.
    # HIGH:     Serious threat, act promptly.
    # CRITICAL: Active attack in progress, immediate response required.
    SEVERITY_LOW = 'low'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_HIGH = 'high'
    SEVERITY_CRITICAL = 'critical'

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, 'Low'),
        (SEVERITY_MEDIUM, 'Medium'),
        (SEVERITY_HIGH, 'High'),
        (SEVERITY_CRITICAL, 'Critical'),
    ]

    # ─── Detection Type Choices ────────────────────────────────────────────
    # Identifies which detection algorithm generated this alert.
    # This allows analysts to distinguish attack patterns:
    #   - TRAFFIC_SPIKE:  Triggered by threshold-based volume analysis
    #                     (requests/minute > configured threshold)
    #   - RATE_LIMIT:     Triggered by per-IP request rate enforcement
    #                     (exceeds the rate_limit_threshold setting)
    #   - MANUAL:         Reserved for future admin-generated alerts
    DETECTION_SPIKE      = 'traffic_spike'
    DETECTION_RATE_LIMIT = 'rate_limit'
    DETECTION_BRUTE_FORCE = 'brute_force'
    DETECTION_FAILED_LOGIN = 'failed_login'
    DETECTION_MANUAL     = 'manual'

    DETECTION_TYPE_CHOICES = [
        (DETECTION_SPIKE,      'Traffic Spike'),
        (DETECTION_RATE_LIMIT, 'Rate Limit Violation'),
        (DETECTION_BRUTE_FORCE, 'Brute Force Attack'),
        (DETECTION_FAILED_LOGIN, 'Failed Login Spike'),
        (DETECTION_MANUAL,     'Manual'),
    ]

    # ─── Fields ───────────────────────────────────────────────────────────
    ip_address = models.CharField(max_length=100, db_index=True)
    # The IP address that triggered the alert (IPv4 or IPv6)

    request_count = models.IntegerField()
    # How many requests this IP made within the detection window

    message = models.TextField()
    # Human-readable description of what was detected

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    # Automatically set to the exact date/time the alert was created

    resolved = models.BooleanField(default=False)
    # False = alert is active/unresolved; True = admin has acknowledged it

    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='resolved_alerts',
    )
    # The user who resolved this alert (null if unresolved or resolved by system)

    resolved_at = models.DateTimeField(null=True, blank=True)
    # Timestamp when the alert was resolved

    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default=SEVERITY_MEDIUM,
    )
    # Severity level — determines visual styling and response urgency

    detection_type = models.CharField(
        max_length=20,
        choices=DETECTION_TYPE_CHOICES,
        default=DETECTION_SPIKE,
    )
    # Which detection engine generated this alert.
    # Default is 'traffic_spike' so all existing alerts remain valid
    # and the system is backwards-compatible after migration.

    # ─── String Representation ────────────────────────────────────────────
    def __str__(self):
        return f"[{self.severity.upper()}] {self.ip_address} — {self.request_count} reqs"

    # ─── Helper Property: Bootstrap Badge Color ───────────────────────────
    # Used in templates to apply the correct Bootstrap color class
    # e.g., bg-danger for critical, bg-warning for medium, etc.
    @property
    def severity_badge(self):
        badge_map = {
            self.SEVERITY_LOW: 'bg-info',
            self.SEVERITY_MEDIUM: 'bg-warning text-dark',
            self.SEVERITY_HIGH: 'bg-orange',          # custom in base.html
            self.SEVERITY_CRITICAL: 'bg-danger',
        }
        return badge_map.get(self.severity, 'bg-secondary')

    @property
    def severity_label(self):
        return self.get_severity_display()

    @property
    def detection_type_label(self):
        """Human-readable detection type for templates and exports."""
        return self.get_detection_type_display()

    @property
    def detection_type_icon(self):
        """Bootstrap Icon class for the detection type badge."""
        icon_map = {
            self.DETECTION_SPIKE:      'bi-graph-up-arrow',
            self.DETECTION_RATE_LIMIT: 'bi-speedometer2',
            self.DETECTION_MANUAL:     'bi-person-fill-gear',
        }
        return icon_map.get(self.detection_type, 'bi-shield-exclamation')

    # ─── Meta: Default ordering (newest alerts first) ─────────────────────
    class Meta:
        ordering = ['-timestamp']



class SystemSettings(models.Model):
    """
    Singleton model to store global system configuration,
    configurable by the Administrator via the UI.
    """
    request_threshold = models.IntegerField(default=5, help_text="Requests per minute before triggering an alert")
    time_window_minutes = models.IntegerField(default=1, help_text="Time window in minutes to evaluate request frequency")
    rate_limit_threshold = models.IntegerField(default=30, help_text="Requests per minute allowed before flagging a rate-limit violation")
    rate_limit_window_minutes = models.IntegerField(default=1, help_text="Time window in minutes to evaluate rate-limit violations")

    # Threat Severity scoring configuration for DDoS Spike Detection
    severity_medium_threshold = models.IntegerField(default=20, help_text="Requests count threshold for MEDIUM severity spike alerts")
    severity_high_threshold = models.IntegerField(default=50, help_text="Requests count threshold for HIGH severity spike alerts")
    severity_critical_threshold = models.IntegerField(default=100, help_text="Requests count threshold for CRITICAL severity spike alerts")

    # Threat Severity scoring configuration for Rate Limiting Violations
    rate_limit_high_multiplier = models.FloatField(default=2.0, help_text="Multiplier for rate limit threshold to trigger HIGH severity alerts")
    rate_limit_critical_multiplier = models.FloatField(default=4.0, help_text="Multiplier for rate limit threshold to trigger CRITICAL severity alerts")

    # Automatic IP Blocking configuration
    enable_auto_blocking = models.BooleanField(default=False, help_text="Enable automatic IP blocking when threshold is exceeded")
    auto_block_threshold = models.IntegerField(default=100, help_text="Request threshold to trigger automatic IP blocking")
    enable_maintenance_mode = models.BooleanField(default=False, help_text="Put the system into maintenance mode (blocks non-admins)")

    data_retention_days = models.IntegerField(
        default=90,
        help_text="Auto-delete traffic logs older than this many days (0 = keep forever)"
    )

    def __str__(self):
        return "Global Detection Settings"

    def save(self, *args, **kwargs):
        self.pk = 1  # Force it to be a singleton
        super(SystemSettings, self).save(*args, **kwargs)
        from django.core.cache import cache
        cache.set("system_settings", self, timeout=300)

    @classmethod
    def get_settings(cls):
        from django.core.cache import cache
        cache_key = "system_settings"
        settings = cache.get(cache_key)
        if settings is None:
            settings, created = cls.objects.get_or_create(pk=1)
            cache.set(cache_key, settings, timeout=300)
        return settings


class RateLimitViolation(models.Model):
    """
    Stores request-rate violations detected by the middleware.
    This preserves a history of high-frequency clients for investigation.
    """
    ip_address = models.CharField(max_length=100, db_index=True)
    request_count = models.IntegerField()
    threshold = models.IntegerField()
    window_minutes = models.IntegerField()
    path = models.CharField(max_length=255)
    request_method = models.CharField(max_length=10)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"RATE LIMIT: {self.ip_address} ({self.request_count}/{self.threshold})"

    class Meta:
        ordering = ['-timestamp']


class IPBlocklist(models.Model):
    """
    Stores IPs that have been blocked by administrators.
    The middleware will return 403 Forbidden to any request from these IPs.
    """
    ip_address = models.CharField(max_length=100, unique=True)
    reason = models.CharField(max_length=255, blank=True)
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey('auth.User', null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"BLOCKED: {self.ip_address}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        from django.core.cache import cache
        cache.set(f"blocked_ip:{self.ip_address}", True, timeout=300)

    def delete(self, *args, **kwargs):
        from django.core.cache import cache
        cache.delete(f"blocked_ip:{self.ip_address}")
        super().delete(*args, **kwargs)

    class Meta:
        ordering = ['-added_at']


class IPWhitelist(models.Model):
    """
    Stores IPs that are whitelisted and should never be blocked.
    The middleware and background detector will bypass blocking logic for these IPs.
    """
    ip_address = models.CharField(max_length=100, unique=True)
    reason = models.CharField(max_length=255, blank=True)
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey('auth.User', null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"WHITELISTED: {self.ip_address}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        from django.core.cache import cache
        cache.set(f"whitelisted_ip:{self.ip_address}", True, timeout=300)

    def delete(self, *args, **kwargs):
        from django.core.cache import cache
        cache.delete(f"whitelisted_ip:{self.ip_address}")
        super().delete(*args, **kwargs)

    class Meta:
        ordering = ['-added_at']


class MonitoringSnapshot(models.Model):
    """
    Stores pre-calculated network activity snapshots generated by the background daemon.
    This allows the dashboard to display the latest monitoring results without database aggregations.
    """
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    req_per_min = models.IntegerField(default=0)
    threshold = models.IntegerField(default=5)
    health = models.CharField(max_length=50, default='normal')
    top_ips_json = models.TextField(default='[]')  # Stores IP metrics rows as serialized JSON

    def __str__(self):
        return f"Snapshot @ {self.timestamp} - Req/min: {self.req_per_min}, Health: {self.health}"

    class Meta:
        ordering = ['-timestamp']


class SimulationRun(models.Model):
    ATTACK_CHOICES = [
        ('normal', 'Normal Traffic'),
        ('spike', 'Traffic Spike'),
        ('rate_limit', 'Rate-Limit Violation'),
        ('ddos', 'DDoS Simulation'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('stopped', 'Stopped'),
        ('failed', 'Failed'),
    ]

    attack_type = models.CharField(max_length=20, choices=ATTACK_CHOICES)
    target_endpoint = models.CharField(max_length=255, default='/')
    num_requests = models.IntegerField(default=100)
    delay_ms = models.IntegerField(default=100)
    simulated_ips_count = models.IntegerField(default=5)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='pending')
    requests_sent = models.IntegerField(default=0)
    requests_blocked = models.IntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    def __str__(self):
        return f"Simulation #{self.id} - {self.get_attack_type_display()} ({self.status})"

    class Meta:
        ordering = ['-started_at']


class AuditLog(models.Model):
    """
    Records all significant user actions for accountability and non-repudiation.
    Every resolve, block, unblock, and settings change is logged here.
    """
    ACTION_CHOICES = [
        ('resolve_alert', 'Resolved Alert'),
        ('reopen_alert', 'Reopened Alert'),
        ('block_ip', 'Blocked IP'),
        ('unblock_ip', 'Unblocked IP'),
        ('whitelist_ip', 'Whitelisted IP'),
        ('remove_whitelist', 'Removed Whitelist'),
        ('update_settings', 'Updated Settings'),
        ('bulk_resolve', 'Bulk Resolved Alerts'),
        ('change_password', 'Changed Password'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='audit_logs',
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    target = models.CharField(max_length=255)
    details = models.TextField(blank=True)
    ip_address = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"{self.user} — {self.get_action_display()} — {self.target}"

    class Meta:
        ordering = ['-timestamp']


class AlertNote(models.Model):
    """
    Investigation notes that analysts can attach to alerts.
    Allows team members to document findings during threat analysis.
    """
    alert = models.ForeignKey(
        Alert, on_delete=models.CASCADE, related_name='notes',
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='alert_notes',
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Note on Alert #{self.alert_id} by {self.author}"

    class Meta:
        ordering = ['created_at']


class SecurityEvent(models.Model):
    EVENT_CHOICES = [
        ('failed_login', 'Failed Login'),
        ('lockout', 'Account Lockout'),
        ('otp_verification', 'OTP Verification'),
        ('successful_login', 'Successful Login'),
        ('logout', 'Successful Logout'),
        ('blocked', 'IP Blocked'),
        ('whitelist', 'IP Whitelists'),
        ('performance_telemetry', 'Performance Telemetry'),
    ]
    ip_address = models.CharField(max_length=100, db_index=True)
    event_type = models.CharField(max_length=50, choices=EVENT_CHOICES, db_index=True)
    username = models.CharField(max_length=150, blank=True, null=True)
    details = models.TextField(blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    source = models.CharField(max_length=50, default='shopsafe')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"[{self.event_type.upper()}] {self.ip_address} — {self.username}"

    class Meta:
        ordering = ['-timestamp']