from django.shortcuts import render
from .models import TrafficLog
from django.core.cache import cache
from alerts.models import IPBlocklist, SystemSettings
from accounts.access import get_user_role

class TrafficLoggingMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Maintenance Mode Enforcement
        settings = SystemSettings.get_settings()
        if settings.enable_maintenance_mode:
            role = get_user_role(request.user)
            # Allow login/logout and django admin pages so admins/users don't get trapped
            allowed_paths = ['/accounts/login/', '/accounts/logout/', '/admin/']
            is_allowed_path = any(request.path.startswith(p) for p in allowed_paths)
            if role not in ['admin', 'analyst'] and not is_allowed_path:
                return render(
                    request,
                    'maintenance.html',
                    context={'message': 'NetWatch Security Center is currently undergoing scheduled maintenance.'},
                    status=503
                )

        # Extract simulated client IP if present (for validation lab simulations), fallback to REMOTE_ADDR
        ip = request.META.get('HTTP_X_NETWATCH_SIMULATED_IP')
        if not ip:
            ip = request.META.get('REMOTE_ADDR')

        # 2. Cache-backed Whitelist Check (implicit whitelist for localhost loopbacks to prevent lockout)
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

        # Store traffic log in database for asynchronous background detection
        # Exclude dashboard background updates, static assets, and admin paths to prevent false-positives
        ignored_prefixes = [
            '/api/',          # Phase 12: Exclude ingest API calls from self-logging
            '/data/',
            '/recent-stats/',
            '/analytics/data/',
            '/static/',
            '/admin/',
            '/accounts/',
            '/simulation/',
        ]
        is_ignored = any(request.path.startswith(prefix) for prefix in ignored_prefixes)

        if not is_ignored:
            TrafficLog.objects.create(
                ip_address=ip,
                url_accessed=request.path,
                request_method=request.method
            )
        
        response = self.get_response(request)
  
        return response
