from django.shortcuts import render
from traffic.models import TrafficLog
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
            allowed_paths = ['/login/', '/logout/', '/admin/']
            is_allowed_path = any(request.path.startswith(p) for p in allowed_paths)
            if role not in ['admin', 'analyst'] and not is_allowed_path:
                return render(
                    request,
                    'maintenance.html',
                    context={'message': 'NetWatch Security Center is currently undergoing scheduled maintenance.'},
                    status=503
                )

        # 1. Extract real client IP (supporting reverse proxies like Nginx/Cloudflare)
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

        # ── Step 3: Mitigation Routing ─────────────────────────────────────
        # The middleware does NOT log any local traffic from NetWatch itself
        # to prevent resource consumption and focus exclusively on ShopSafe logs
        # forwarded via the Ingest API.
        
        response = self.get_response(request)
        return response
