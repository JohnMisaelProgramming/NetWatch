from django.shortcuts import render
from traffic.models import TrafficLog
from django.core.cache import cache
from alerts.models import IPBlocklist, SystemSettings
from accounts.access import get_user_role


def _is_device_blocked(user_agent):
    """
    Checks if the given User-Agent matches any entry in the DeviceBlocklist.

    Uses a 60-second cache to avoid hitting the database on every single request.
    The cache is automatically invalidated when a DeviceBlocklist entry is
    created or deleted (see DeviceBlocklist.save() and .delete()).

    Returns the matched DeviceBlocklist identifier string if blocked, or None.
    """
    if not user_agent:
        return None

    # Retrieve all device blocklist entries from cache (or DB on cache miss)
    entries = cache.get('device_blocklist_entries')
    if entries is None:
        from alerts.models import DeviceBlocklist
        entries = list(
            DeviceBlocklist.objects.values_list('identifier', 'match_type')
        )
        cache.set('device_blocklist_entries', entries, timeout=60)

    # Check each entry against the incoming User-Agent
    ua_lower = user_agent.lower()
    for identifier, match_type in entries:
        if match_type == 'exact':
            if user_agent == identifier:
                return identifier
        else:  # 'contains' (default)
            if identifier.lower() in ua_lower:
                return identifier

    return None


class TrafficLoggingMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Maintenance Mode Enforcement
        settings = SystemSettings.get_settings()
        if settings.enable_maintenance_mode:
            role = get_user_role(request.user)
            # Allow login/logout and django admin pages so admins/users don't get trapped
            allowed_paths = ['/login/', '/logout/', '/admin/']
            is_allowed_path = any(request.path.startswith(p) for p in allowed_paths)
            if role not in ['admin', 'analyst'] and not is_allowed_path:
                return render(
                    request,
                    'maintenance.html',
                    context={'message': 'NetWatch Security Center is currently undergoing scheduled maintenance.'},
                    status=503
                )

        # 2. Extract real client IP (supporting reverse proxies like Nginx/Cloudflare)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            # Direct socket connection
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
            # Trust simulated IP ONLY for direct local loopback calls (no proxies)
            if ip in ('127.0.0.1', '::1'):
                simulated_ip = request.META.get('HTTP_X_NETWATCH_SIMULATED_IP')
                if simulated_ip:
                    ip = simulated_ip

        # 3. Extract User-Agent for device blocking
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # 4. Device Blocklist Check
        # Block requests from tools/devices whose User-Agent matches a blocked pattern
        blocked_device = _is_device_blocked(user_agent)
        if blocked_device:
            # Allow admin/login paths so administrators can still manage the blocklist
            admin_paths = ['/login/', '/logout/', '/admin/', '/api/']
            is_admin_path = any(request.path.startswith(p) for p in admin_paths)
            if not is_admin_path:
                return render(
                    request,
                    '403.html',
                    context={
                        'is_blocked_ip': False,
                        'is_blocked_device': True,
                        'blocked_device_pattern': blocked_device,
                    },
                    status=403
                )

        # 5. Cache-backed Whitelist Check (implicit whitelist for localhost loopbacks to prevent lockout)
        if ip in ['127.0.0.1', '::1']:
            is_whitelisted = True
        else:
            cache_whitelist_key = f"whitelisted_ip:{ip}"
            is_whitelisted = cache.get(cache_whitelist_key)
            if is_whitelisted is None:
                from alerts.models import IPWhitelist
                is_whitelisted = IPWhitelist.objects.filter(ip_address=ip).exists()
                cache.set(cache_whitelist_key, is_whitelisted, timeout=300)

        if is_whitelisted:
            is_blocked = False
        else:
            # Cache-backed blocklist lookup to eliminate request-path DB query overhead
            cache_key = f"blocked_ip:{ip}"
            is_blocked = cache.get(cache_key)

            if is_blocked is None:
                is_blocked = IPBlocklist.objects.filter(ip_address=ip).exists()
                cache.set(cache_key, is_blocked, timeout=300)  # Cache status for 5 minutes

        if is_blocked:
            return render(
                request,
                '403.html',
                context={
                    'is_blocked_ip': True,
                },
                status=403
            )

        # ── Step 6: Traffic Logging ────────────────────────────────────────
        # Log requests that arrive directly at NetWatch so the detection engine
        # can analyze them. This ensures terminal-based attacks (curl, scripts,
        # attack_test.py) targeting port 8000 are detected by run_detector.
        #
        # We skip logging for:
        #   - Static files, media, and admin pages (noise reduction)
        #   - API endpoints (ingest API traffic is logged separately)
        #   - Whitelisted/localhost IPs (they are trusted)
        ignored_prefixes = ['/static/', '/media/', '/admin/', '/api/']
        is_ignored = any(request.path.startswith(prefix) for prefix in ignored_prefixes)

        if not is_ignored and not is_whitelisted:
            TrafficLog.objects.create(
                ip_address=ip,
                url_accessed=request.path,
                request_method=request.method,
                user_agent=user_agent[:500],  # Truncate to field max_length
            )

        response = self.get_response(request)
        return response
