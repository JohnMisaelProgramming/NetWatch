from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse

from accounts.access import role_required
from .models import Alert, SystemSettings, IPBlocklist, RateLimitViolation, SimulationRun, IPWhitelist
from traffic.models import TrafficLog
from .simulation import start_simulation_thread, stop_simulation_thread


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Alert management is limited to Administrators and Security Analysts.')
def alerts_list(request):
    """
    Alert Management List View.

    Supports filtering by:
    - status (all / active / resolved)
    - severity (all / low / medium / high / critical)
    - date_from / date_to (date range)

    Uses Django's Paginator to show 15 alerts per page.
    Supports incident response workflows by allowing analysts
    to quickly filter and triage alerts.
    """
    alerts_qs = Alert.objects.all()

    # ── Filters from GET query parameters ──────────────────────────────
    status   = request.GET.get('status', '')
    severity = request.GET.get('severity', '')
    detection_type = request.GET.get('detection_type', '')
    date_from = request.GET.get('date_from', '')
    date_to   = request.GET.get('date_to', '')

    if status == 'active':
        alerts_qs = alerts_qs.filter(resolved=False)
    elif status == 'resolved':
        alerts_qs = alerts_qs.filter(resolved=True)

    if severity:
        alerts_qs = alerts_qs.filter(severity=severity)

    if detection_type:
        alerts_qs = alerts_qs.filter(detection_type=detection_type)

    if date_from:
        alerts_qs = alerts_qs.filter(timestamp__date__gte=date_from)
    if date_to:
        alerts_qs = alerts_qs.filter(timestamp__date__lte=date_to)

    # ── Pagination ──────────────────────────────────────────────────────
    paginator  = Paginator(alerts_qs, 15)
    page_number = request.GET.get('page')
    page_obj   = paginator.get_page(page_number)

    # ── Summary stats for KPI row ────────────────────────────────────
    context = {
        'page_obj': page_obj,
        'status':   status,
        'severity': severity,
        'detection_type': detection_type,
        'date_from': date_from,
        'date_to':   date_to,

        # KPI counts (always from full dataset, not the filtered one)
        'total_count':    Alert.objects.count(),
        'active_count':   Alert.objects.filter(resolved=False).count(),
        'resolved_count': Alert.objects.filter(resolved=True).count(),
        'critical_count': Alert.objects.filter(severity='critical', resolved=False).count(),
    }
    return render(request, 'alerts/alerts_list.html', context)


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Alert details are limited to Administrators and Security Analysts.')
def alert_detail(request, pk):
    """
    Alert Detail View.

    Shows full information about a single alert:
    - Alert metadata (IP, severity, message, timestamp)
    - Related traffic from that IP address (forensic timeline)
    - Alert history for that IP (repeat offender analysis)

    This supports incident response by giving analysts all the
    context they need to understand and act on a specific threat.
    """
    alert = get_object_or_404(Alert, pk=pk)

    # All traffic logged from this IP address (most recent first)
    related_traffic = (
        TrafficLog.objects
        .filter(ip_address=alert.ip_address)
        .order_by('-timestamp')[:25]
    )

    # All alerts ever generated for this IP (alert history)
    ip_alert_history = (
        Alert.objects
        .filter(ip_address=alert.ip_address)
        .order_by('-timestamp')[:10]
    )

    # Is this a repeat offender? (more than 1 alert from this IP)
    is_repeat = Alert.objects.filter(ip_address=alert.ip_address).count() > 1

    context = {
        'alert':            alert,
        'related_traffic':  related_traffic,
        'ip_alert_history': ip_alert_history,
        'is_repeat':        is_repeat,
        'traffic_count':    TrafficLog.objects.filter(ip_address=alert.ip_address).count(),
    }
    return render(request, 'alerts/alert_detail.html', context)


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Only Administrators and Security Analysts can resolve alerts.')
def resolve_alert(request, pk):
    """
    Resolve Alert Action (POST only).

    Marks an alert as resolved (resolved=True).
    Only accepts POST requests to prevent accidental resolution via
    URL clicking (which would be a GET request).

    After resolving, redirects to the 'next' URL if provided,
    otherwise falls back to the alert list.
    """
    if request.method == 'POST':
        alert = get_object_or_404(Alert, pk=pk)
        alert.resolved = True
        alert.save()

        messages.success(
            request,
            f'✓ Alert #{pk} from IP {alert.ip_address} ({alert.get_severity_display()} severity) '
            f'has been marked as resolved.'
        )

    # 'next' allows resolving from the detail page and returning there,
    # or resolving from the list and staying on the list.
    next_url = request.POST.get('next', 'alerts_list')
    return redirect(next_url)


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can configure system settings.')
def settings_view(request):
    """
    Unified Administrator Control Panel & Health Hub.
    Restricted to Administrator role.
    """
    import os
    import platform
    from django.utils import timezone
    from django.conf import settings as django_settings
    from django.core.cache import cache
    
    settings = SystemSettings.get_settings()
    whitelisted_ips = IPWhitelist.objects.all().order_by('-added_at')

    # Post processing for System Settings form save
    if request.method == 'POST':
        try:
            threshold = int(request.POST.get('request_threshold', 5))
            time_window = int(request.POST.get('time_window_minutes', 1))
            rate_limit_threshold = int(request.POST.get('rate_limit_threshold', 30))
            rate_limit_window_minutes = int(request.POST.get('rate_limit_window_minutes', 1))
            
            severity_medium = int(request.POST.get('severity_medium_threshold', 20))
            severity_high = int(request.POST.get('severity_high_threshold', 50))
            severity_critical = int(request.POST.get('severity_critical_threshold', 100))
            rate_limit_high_mult = float(request.POST.get('rate_limit_high_multiplier', 2.0))
            rate_limit_critical_mult = float(request.POST.get('rate_limit_critical_multiplier', 4.0))

            enable_auto_blocking = 'enable_auto_blocking' in request.POST
            auto_block_threshold = int(request.POST.get('auto_block_threshold', 100))
            enable_maintenance_mode = 'enable_maintenance_mode' in request.POST

            settings.request_threshold = threshold
            settings.time_window_minutes = time_window
            settings.rate_limit_threshold = rate_limit_threshold
            settings.rate_limit_window_minutes = rate_limit_window_minutes
            
            settings.severity_medium_threshold = severity_medium
            settings.severity_high_threshold = severity_high
            settings.severity_critical_threshold = severity_critical
            settings.rate_limit_high_multiplier = rate_limit_high_mult
            settings.rate_limit_critical_multiplier = rate_limit_critical_mult

            settings.enable_auto_blocking = enable_auto_blocking
            settings.auto_block_threshold = auto_block_threshold
            settings.enable_maintenance_mode = enable_maintenance_mode
            
            settings.save()
            
            messages.success(request, 'System settings updated successfully.')
            return redirect('settings')
        except ValueError:
            messages.error(request, 'Invalid input. Please enter valid numbers.')

    # System Health Dashboard calculations
    last_run = cache.get("detector_last_run")
    detector_running = False
    last_run_str = "Never"
    if last_run:
        detector_running = (timezone.now() - last_run).total_seconds() < 20
        last_run_str = last_run.strftime("%H:%M:%S")

    # platform specs
    os_name = f"{platform.system()} {platform.release()}"
    cpu_cores = os.cpu_count() or 1
    
    cpu_percent = "N/A"
    ram_percent = "N/A"
    try:
        import psutil
        cpu_percent = f"{psutil.cpu_percent()}%"
        ram_percent = f"{psutil.virtual_memory().percent}%"
    except ImportError:
        pass

    # database status
    db_engine = django_settings.DATABASES['default']['ENGINE']
    db_path = django_settings.DATABASES['default']['NAME']
    db_size = "N/A"
    if 'sqlite' in db_engine.lower() or 'sqlite' in db_path.lower():
        try:
            if os.path.exists(db_path):
                size_bytes = os.path.getsize(db_path)
                db_size = f"{size_bytes / (1024 * 1024):.2f} MB"
        except Exception:
            pass

    # Database record counts
    db_stats = {
        'traffic_logs': TrafficLog.objects.count(),
        'alerts': Alert.objects.count(),
        'rate_violations': RateLimitViolation.objects.count(),
        'blocked_ips': IPBlocklist.objects.count(),
        'whitelisted_ips': whitelisted_ips.count(),
        'db_size': db_size,
        'db_engine': db_engine.split('.')[-1].upper(),
    }

    context = {
        'settings': settings,
        'whitelisted_ips': whitelisted_ips,
        'detector_running': detector_running,
        'detector_last_run': last_run_str,
        'os_name': os_name,
        'cpu_cores': cpu_cores,
        'cpu_percent': cpu_percent,
        'ram_percent': ram_percent,
        'db_stats': db_stats,
    }
    return render(request, 'alerts/settings.html', context)


@role_required('admin', redirect_url='dashboard', message='Access Denied: Whitelist changes are limited to Administrators.')
def whitelist_add_ip(request):
    """
    Manually add an IP address to the whitelist to prevent it from ever being blocked.
    """
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '').strip()
        reason = request.POST.get('reason', '').strip()

        if ip_address:
            # Check if already whitelisted
            if IPWhitelist.objects.filter(ip_address=ip_address).exists():
                messages.warning(request, f'IP address {ip_address} is already whitelisted.')
            else:
                # Remove from blocklist if whitelisting it
                IPBlocklist.objects.filter(ip_address=ip_address).delete()
                # Clear blocked cache
                from django.core.cache import cache
                cache.delete(f"blocked_ip:{ip_address}")
                
                IPWhitelist.objects.create(
                    ip_address=ip_address,
                    reason=reason or 'Manually whitelisted by Administrator.',
                    added_by=request.user
                )
                messages.success(request, f'IP address {ip_address} has been whitelisted.')
        else:
            messages.error(request, 'Please provide a valid IP address.')
            
    return redirect('settings')


@role_required('admin', redirect_url='dashboard', message='Access Denied: Whitelist changes are limited to Administrators.')
def whitelist_delete_ip(request, pk):
    """
    Remove an IP address from the whitelist.
    """
    if request.method == 'POST':
        item = get_object_or_404(IPWhitelist, pk=pk)
        ip = item.ip_address
        item.delete()
        messages.success(request, f'IP address {ip} has been removed from the whitelist.')
    return redirect('settings')


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Rate-limit history is limited to Administrators and Security Analysts.')
def rate_limit_history(request):
    """
    Review page for request-rate violations detected by the middleware.

    This supports incident investigation by showing which IPs repeatedly
    exceeded the configured request-rate limit and when the violations occurred.
    """
    violations_qs = RateLimitViolation.objects.all()

    ip_address = request.GET.get('ip_address', '').strip()
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    if ip_address:
        violations_qs = violations_qs.filter(ip_address__icontains=ip_address)
    if date_from:
        violations_qs = violations_qs.filter(timestamp__date__gte=date_from)
    if date_to:
        violations_qs = violations_qs.filter(timestamp__date__lte=date_to)

    paginator = Paginator(violations_qs, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'ip_address': ip_address,
        'date_from': date_from,
        'date_to': date_to,
        'total_violations': RateLimitViolation.objects.count(),
        'unique_ips': RateLimitViolation.objects.values('ip_address').distinct().count(),
        'most_recent': RateLimitViolation.objects.first(),
    }
    return render(request, 'alerts/rate_limit_history.html', context)


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can view the blocklist.')
def blocklist_view(request):
    """
    Displays the current IP blocklist.
    """
    blocklist = IPBlocklist.objects.all()
    return render(request, 'alerts/blocklist.html', {'blocklist': blocklist})


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can block IP addresses.')
def block_ip(request, pk):
    """
    Action to add an IP from an alert to the blocklist.
    """
    if request.method == 'POST':
        if not hasattr(request.user, 'profile') or request.user.profile.role not in ['admin', 'analyst']:
            messages.error(request, 'Access Denied: Only Administrators and Analysts can block IPs.')
            return redirect('alerts_list')

        alert = get_object_or_404(Alert, pk=pk)
        
        # Add to blocklist if not already present
        if not IPBlocklist.objects.filter(ip_address=alert.ip_address).exists():
            IPBlocklist.objects.create(
                ip_address=alert.ip_address,
                reason=f"Blocked from Alert #{alert.id} ({alert.severity})",
                added_by=request.user
            )
            messages.success(request, f'IP {alert.ip_address} has been added to the blocklist.')
        else:
            messages.warning(request, f'IP {alert.ip_address} is already in the blocklist.')
            
    next_url = request.POST.get('next', 'alerts_list')
    return redirect(next_url)

@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can unblock IP addresses.')
def unblock_ip(request, pk):
    """
    Action to remove an IP from the blocklist.
    """
    if request.method == 'POST':
        if not hasattr(request.user, 'profile') or request.user.profile.role != 'admin':
            messages.error(request, 'Access Denied: Only Administrators can unblock IPs.')
            return redirect('blocklist')

        blocked_ip = get_object_or_404(IPBlocklist, pk=pk)
        ip_addr = blocked_ip.ip_address
        blocked_ip.delete()
        messages.success(request, f'IP {ip_addr} has been removed from the blocklist.')

    return redirect('blocklist')


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can manually add IPs to the blocklist.')
def blocklist_add_ip(request):
    """
    Manual Add IP to Blocklist view.

    Allows an Administrator to block any IP address directly,
    without requiring a pre-existing alert for that IP.

    Features:
    - IPv4 and IPv6 format validation via Python's built-in ipaddress module
    - Duplicate prevention (prevents the same IP being added twice)
    - Optional block reason (stored for audit trail)
    - Records which admin added the block and when (added_by / added_at)

    Cybersecurity value: Supports proactive blocking — an admin can block
    a known-malicious IP from a threat intelligence feed before it ever
    generates an alert in NetWatch.

    Satisfies Objective 5: IP-level control and breakdown of threat sources.
    """
    import ipaddress  # Standard library — no extra install required

    if request.method == 'POST':
        raw_ip = request.POST.get('ip_address', '').strip()
        reason = request.POST.get('reason', '').strip()

        # ── Validation 1: Field must not be empty ───────────────────────────
        if not raw_ip:
            messages.error(request, 'IP address field cannot be empty.')
            return redirect('blocklist')

        # ── Validation 2: Must be a valid IPv4 or IPv6 address ─────────────
        # ipaddress.ip_address() raises ValueError for anything that is not
        # a valid IP (e.g. "foo", "256.1.1.1", "999::xyz").
        try:
            ipaddress.ip_address(raw_ip)
        except ValueError:
            messages.error(
                request,
                f'"{raw_ip}" is not a valid IPv4 or IPv6 address. '
                f'Example valid formats: 192.168.1.10 or 2001:db8::1'
            )
            return redirect('blocklist')

        # ── Validation 3: Duplicate prevention ─────────────────────────────
        # Check for an exact match only — partial IP blocking is not supported
        # as it could cause unintended collateral blocking.
        if IPBlocklist.objects.filter(ip_address=raw_ip).exists():
            messages.warning(request, f'IP {raw_ip} is already in the blocklist.')
            return redirect('blocklist')

        # ── Create the blocklist entry ──────────────────────────────────────
        IPBlocklist.objects.create(
            ip_address=raw_ip,
            # If no reason was provided, store a default audit note
            reason=reason or 'Manually blocked by administrator',
            # Record which admin performed the action for audit trail
            added_by=request.user,
        )

        messages.success(
            request,
            f'IP {raw_ip} has been added to the blocklist. '
            f'All future requests from this address will be blocked (403).'
        )

    # Always redirect back to the blocklist page whether GET or POST
    return redirect('blocklist')


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can access the Simulation Validation Lab.')
def simulation_lab(request):
    """
    Renders the Administrator Security Validation Lab dashboard.
    """
    simulations = SimulationRun.objects.all().order_by('-started_at')
    
    # Calculate aggregate stats
    total_sims = simulations.count()
    completed_sims = simulations.filter(status='completed').count()
    stopped_sims = simulations.filter(status='stopped').count()
    failed_sims = simulations.filter(status='failed').count()
    active_sims = simulations.filter(status='running').count()

    context = {
        'simulations': simulations,
        'total_sims': total_sims,
        'completed_sims': completed_sims,
        'stopped_sims': stopped_sims,
        'failed_sims': failed_sims,
        'active_sims': active_sims,
    }
    return render(request, 'alerts/simulation_lab.html', context)


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can trigger simulations.')
def start_simulation(request):
    """
    POST action to configure and spawn a traffic simulation thread.
    """
    if request.method == 'POST':
        attack_type = request.POST.get('attack_type', 'normal')
        target_endpoint = request.POST.get('target_endpoint', '/').strip()
        
        # Safe default parsing
        try:
            num_requests = int(request.POST.get('num_requests', 100))
            delay_ms = int(request.POST.get('delay_ms', 100))
            simulated_ips_count = int(request.POST.get('simulated_ips_count', 5))
        except ValueError:
            messages.error(request, 'Invalid input parameters. Please enter valid numbers.')
            return redirect('simulation_lab')

        # Limit bounds to protect localhost from accidental self-DOS
        num_requests = min(max(1, num_requests), 5000)
        delay_ms = min(max(0, delay_ms), 5000)
        simulated_ips_count = min(max(1, simulated_ips_count), 100)

        # Enforce target endpoint starts with /
        if not target_endpoint.startswith('/'):
            target_endpoint = '/' + target_endpoint

        # Check if there is already an active running simulation to avoid thread flooding
        if SimulationRun.objects.filter(status='running').exists():
            messages.warning(request, 'A traffic simulation is already active. Please wait or stop it first.')
            return redirect('simulation_lab')

        # Create simulation run configuration
        sim = SimulationRun.objects.create(
            attack_type=attack_type,
            target_endpoint=target_endpoint,
            num_requests=num_requests,
            delay_ms=delay_ms,
            simulated_ips_count=simulated_ips_count,
            status='pending'
        )

        # Phase 12: Determine target base URL.
        # Since simulations now attack ShopSafe directly, we target port 8080.
        base_url = 'http://127.0.0.1:8080/'

        # Start thread
        start_simulation_thread(sim.id, base_url)
        messages.success(request, f'✓ Simulation #{sim.id} ({sim.get_attack_type_display()}) started in the background.')

    return redirect('simulation_lab')


@role_required('admin', redirect_url='dashboard', message='Access Denied: Only Administrators can stop simulations.')
def stop_simulation(request, pk):
    """
    POST action to stop an active simulation thread.
    """
    if request.method == 'POST':
        sim = get_object_or_404(SimulationRun, pk=pk)
        if sim.status == 'running':
            stop_simulation_thread(sim.id)
            messages.info(request, f'Termination signal sent to Simulation #{sim.id}.')
        else:
            messages.warning(request, f'Simulation #{sim.id} is not currently running.')
            
    return redirect('simulation_lab')


@role_required('admin', redirect_url='dashboard', message='Access Denied: Simulation metrics are limited to Administrators.')
def simulation_status_api(request):
    """
    JSON API endpoint to poll active simulation statistics.
    """
    active_runs = SimulationRun.objects.filter(status='running')
    data = []
    for run in active_runs:
        processed = run.requests_sent + run.requests_blocked
        progress_pct = round(processed / run.num_requests * 100) if run.num_requests > 0 else 0
        data.append({
            'id': run.id,
            'requests_sent': run.requests_sent,
            'requests_blocked': run.requests_blocked,
            'total_requests': run.num_requests,
            'progress_pct': min(100, progress_pct),
            'status': run.status,
            'attack_label': run.get_attack_type_display(),
        })
    return JsonResponse({'active_simulations': data})


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Only Administrators and Analysts can access the Investigation Center.')
def ip_investigation(request):
    """
    Triage and forensic scoping interface for Security Analysts and Admins.
    Supports individual IP investigations (Dossier Mode) or global timeline triage.
    """
    from django.db.models import Q, Count
    from django.urls import reverse
    ip = request.GET.get('ip', '').strip()

    if ip:
        # ── 1. INDIVIDUAL IP INVESTIGATION MODE ────────────────────────────
        # Fetch blocklist status
        is_blocked = IPBlocklist.objects.filter(ip_address=ip).exists()
        block_record = IPBlocklist.objects.filter(ip_address=ip).first()

        # Traffic aggregation stats
        logs_qs = TrafficLog.objects.filter(ip_address=ip)
        total_requests = logs_qs.count()

        first_log = logs_qs.order_by('timestamp').first()
        last_log = logs_qs.order_by('-timestamp').first()

        # Compute active attack presence / duration
        duration_str = "N/A"
        if first_log and last_log:
            delta = last_log.timestamp - first_log.timestamp
            days = delta.days
            hours, remainder = divmod(delta.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if days > 0:
                duration_str = f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                duration_str = f"{hours}h {minutes}m {seconds}s"
            else:
                duration_str = f"{minutes}m {seconds}s"

        # Alerts & rate limit violations counters
        active_alerts_count = Alert.objects.filter(ip_address=ip, resolved=False).count()
        resolved_alerts_count = Alert.objects.filter(ip_address=ip, resolved=True).count()
        violations_count = RateLimitViolation.objects.filter(ip_address=ip).count()

        # Dynamic Threat Score Logic
        if is_blocked or active_alerts_count >= 3:
            threat_level = 'critical'
            threat_color = 'var(--nw-danger)'
            threat_icon = 'bi-exclamation-octagon-fill'
        elif active_alerts_count >= 1 or violations_count >= 5:
            threat_level = 'high'
            threat_color = 'var(--nw-orange)'
            threat_icon = 'bi-exclamation-triangle-fill'
        elif violations_count >= 1 or resolved_alerts_count > 0:
            threat_level = 'medium'
            threat_color = 'var(--nw-warning)'
            threat_icon = 'bi-dash-circle-fill'
        else:
            threat_level = 'low'
            threat_color = 'var(--nw-success)'
            threat_icon = 'bi-shield-check'

        # Endpoint target distributions
        top_endpoints = (
            logs_qs
            .values('url_accessed')
            .annotate(count=Count('id'))
            .order_by('-count')[:5]
        )

        # Timelines
        alerts = Alert.objects.filter(ip_address=ip).order_by('-timestamp')
        violations = RateLimitViolation.objects.filter(ip_address=ip).order_by('-timestamp')

        # Paginated Request History Log
        paginator = Paginator(logs_qs.order_by('-timestamp'), 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        context = {
            'mode': 'dossier',
            'ip': ip,
            'is_blocked': is_blocked,
            'block_record': block_record,
            'total_requests': total_requests,
            'duration_str': duration_str,
            'first_log': first_log,
            'last_log': last_log,
            'active_alerts_count': active_alerts_count,
            'resolved_alerts_count': resolved_alerts_count,
            'violations_count': violations_count,
            'threat_level': threat_level,
            'threat_color': threat_color,
            'threat_icon': threat_icon,
            'top_endpoints': top_endpoints,
            'alerts': alerts,
            'violations': violations,
            'page_obj': page_obj,
        }
    else:
        # ── 2. GLOBAL TIMELINE TRIAGE MODE ─────────────────────────────────
        alerts_qs = Alert.objects.all()
        violations_qs = RateLimitViolation.objects.all()

        total_alerts = alerts_qs.count()
        unresolved_alerts = alerts_qs.filter(resolved=False).count()
        total_violations = violations_qs.count()

        # Severity breakdown
        severity_counts = {
            'critical': alerts_qs.filter(severity='critical').count(),
            'high': alerts_qs.filter(severity='high').count(),
            'medium': alerts_qs.filter(severity='medium').count(),
            'low': alerts_qs.filter(severity='low').count(),
        }

        # Top offending IP addresses
        top_offenders = (
            Alert.objects
            .values('ip_address')
            .annotate(
                alert_count=Count('id'),
                unresolved_count=Count('id', filter=Q(resolved=False))
            )
            .order_by('-alert_count')[:10]
        )

        # Build chronological feed of recent alerts and violations
        recent_alerts = Alert.objects.all().order_by('-timestamp')[:15]
        recent_violations = RateLimitViolation.objects.all().order_by('-timestamp')[:15]

        incident_timeline = []
        for alert in recent_alerts:
            incident_timeline.append({
                'id': alert.id,
                'type': 'alert',
                'timestamp': alert.timestamp,
                'ip': alert.ip_address,
                'message': alert.message,
                'severity': alert.severity,
                'badge': alert.severity_badge,
                'label': alert.get_detection_type_display(),
                'resolved': alert.resolved,
                'detail_url': reverse('alert_detail', args=[alert.pk]),
            })

        for violation in recent_violations:
            incident_timeline.append({
                'id': violation.id,
                'type': 'violation',
                'timestamp': violation.timestamp,
                'ip': violation.ip_address,
                'message': violation.message,
                'severity': 'medium',
                'badge': 'bg-warning text-dark',
                'label': 'Rate Violation',
                'resolved': True,
                'detail_url': reverse('rate_limit_history') + f"?ip_address={violation.ip_address}",
            })

        # Sort combined timeline (newest first)
        incident_timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        incident_timeline = incident_timeline[:20]

        context = {
            'mode': 'timeline',
            'total_alerts': total_alerts,
            'unresolved_alerts': unresolved_alerts,
            'total_violations': total_violations,
            'severity_counts': severity_counts,
            'top_offenders': top_offenders,
            'timeline': incident_timeline,
        }

    return render(request, 'alerts/investigate.html', context)


