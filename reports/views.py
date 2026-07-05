import csv
import io

from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.utils import timezone
from django.db.models import Count

from accounts.access import role_required
from traffic.models import TrafficLog
from alerts.models import Alert


def _get_filtered_querysets(request):
    """
    Helper: applies ALL active filter parameters from GET to TrafficLog and
    Alert querysets.

    Supported filters:
      date_from / date_to  — existing date range filter (preserved)
      ip_address           — partial match on IP (new)
      url_search           — partial match on URL accessed (new, traffic only)
      severity             — exact match on alert severity (new)
      alert_status         — active / resolved filter (new)
      sort                 — field to order Alert queryset by (new)

    Returns (traffic_qs, alerts_qs, filters_dict) so every view can access
    the active filter values for template rendering without re-reading request.GET.
    """
    # ── Collect all filter parameters ──────────────────────────────────────
    date_from      = request.GET.get('date_from', '').strip()
    date_to        = request.GET.get('date_to', '').strip()
    ip_address     = request.GET.get('ip_address', '').strip()
    url_search     = request.GET.get('url_search', '').strip()
    severity       = request.GET.get('severity', '').strip()
    alert_status   = request.GET.get('alert_status', '').strip()
    detection_type = request.GET.get('detection_type', '').strip()
    request_method = request.GET.get('request_method', '').strip().upper()
    sort           = request.GET.get('sort', '-timestamp').strip()

    # Whitelist allowed sort fields to prevent arbitrary ORM injection
    ALLOWED_SORTS = {
        'timestamp':   'timestamp',
        '-timestamp':  '-timestamp',
        'severity':    'severity',
        '-severity':   '-severity',
        'request_count': 'request_count',
        '-request_count': '-request_count',
        'ip_address':  'ip_address',
        '-ip_address': '-ip_address',
    }
    safe_sort = ALLOWED_SORTS.get(sort, '-timestamp')

    # ── Base querysets ──────────────────────────────────────────────────────
    traffic_qs = TrafficLog.objects.all()
    alerts_qs  = Alert.objects.all()

    # ── Date range (existing, preserved) ───────────────────────────────────
    if date_from:
        traffic_qs = traffic_qs.filter(timestamp__date__gte=date_from)
        alerts_qs  = alerts_qs.filter(timestamp__date__gte=date_from)
    if date_to:
        traffic_qs = traffic_qs.filter(timestamp__date__lte=date_to)
        alerts_qs  = alerts_qs.filter(timestamp__date__lte=date_to)

    # ── IP Address search (new) — applies to both traffic and alerts ────────
    # icontains = case-insensitive partial match, so "192.168" matches
    # "192.168.1.1", "192.168.0.50", etc.
    if ip_address:
        traffic_qs = traffic_qs.filter(ip_address__icontains=ip_address)
        alerts_qs  = alerts_qs.filter(ip_address__icontains=ip_address)

    # ── URL search (new) — applies to traffic only ──────────────────────────
    if url_search:
        traffic_qs = traffic_qs.filter(url_accessed__icontains=url_search)

    # ── Severity filter (new) — applies to alerts only ─────────────────────
    if severity in ('low', 'medium', 'high', 'critical'):
        alerts_qs = alerts_qs.filter(severity=severity)

    # ── Alert status filter (new) — active / resolved ──────────────────────
    if alert_status == 'active':
        alerts_qs = alerts_qs.filter(resolved=False)
    elif alert_status == 'resolved':
        alerts_qs = alerts_qs.filter(resolved=True)

    # ── Detection Type filter — applies to alerts only ─────────────────────
    if detection_type in ('traffic_spike', 'rate_limit', 'manual'):
        alerts_qs = alerts_qs.filter(detection_type=detection_type)

    # ── Request Method filter — applies to traffic only ─────────────────────
    if request_method in ('GET', 'POST', 'PUT', 'DELETE'):
        traffic_qs = traffic_qs.filter(request_method=request_method)

    # ── Sorting (new) — applied to alerts queryset ──────────────────────────
    alerts_qs = alerts_qs.order_by(safe_sort)

    # Bundle all active filter values into a dict for template rendering
    filters = {
        'date_from':      date_from,
        'date_to':        date_to,
        'ip_address':     ip_address,
        'url_search':     url_search,
        'severity':       severity,
        'alert_status':   alert_status,
        'detection_type': detection_type,
        'request_method': request_method,
        'sort':           sort,
    }

    return traffic_qs, alerts_qs, filters


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Reports are limited to Administrators and Security Analysts.')
def reports_home(request):
    """
    Reports & Audit landing page.

    Displays:
    - Summary statistics (filterable by date range, IP, URL, severity, status)
    - Top attacking IPs
    - Alert history summary table (paginated, 15 per page, sortable)
    - Export buttons (CSV and PDF for both traffic and alerts)

    Supports the research objective of documenting and evaluating network threats
    through structured, exportable reports.
    """
    traffic_qs, alerts_qs, filters = _get_filtered_querysets(request)

    # ── Summary Stats ──────────────────────────────────────────────────────
    total_traffic  = traffic_qs.count()
    total_alerts   = alerts_qs.count()
    active_alerts  = alerts_qs.filter(resolved=False).count()
    resolved_count = alerts_qs.filter(resolved=True).count()

    severity_summary = {
        'critical': alerts_qs.filter(severity='critical').count(),
        'high':     alerts_qs.filter(severity='high').count(),
        'medium':   alerts_qs.filter(severity='medium').count(),
        'low':      alerts_qs.filter(severity='low').count(),
    }

    # ── Top Attacking IPs ──────────────────────────────────────────────────
    top_attacking_ips = (
        alerts_qs
        .values('ip_address')
        .annotate(alert_count=Count('id'))
        .order_by('-alert_count')[:10]
    )

    # ── Top Traffic IPs ────────────────────────────────────────────────────
    top_traffic_ips = (
        traffic_qs
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )

    # ── Alert History — paginated (15 per page) ────────────────────────────
    # alerts_qs is already sorted by the chosen sort field (default: -timestamp)
    paginator   = Paginator(alerts_qs, 15)
    page_number = request.GET.get('page')
    page_obj    = paginator.get_page(page_number)

    # ── Traffic Activity Log — paginated (15 per page) ──────────────────────
    traffic_paginator = Paginator(traffic_qs.order_by('-timestamp'), 15)
    traffic_page_number = request.GET.get('traffic_page')
    traffic_page_obj = traffic_paginator.get_page(traffic_page_number)

    # ── Unique IPs ─────────────────────────────────────────────────────────
    unique_ips = traffic_qs.values('ip_address').distinct().count()

    # Determine tab state
    active_tab = request.GET.get('tab', 'alerts')
    if active_tab not in ('alerts', 'traffic'):
        active_tab = 'alerts'

    # Security IP lists for reputation badges
    from alerts.models import IPBlocklist
    blocked_ips = set(IPBlocklist.objects.values_list('ip_address', flat=True))
    alerted_ips = set(Alert.objects.filter(resolved=False).values_list('ip_address', flat=True))

    context = {
        # Filter values — passed back to the template so form fields
        # retain their values after submission (standard UX pattern).
        **filters,

        # Summary KPIs
        'total_traffic':     total_traffic,
        'total_alerts':      total_alerts,
        'active_alerts':     active_alerts,
        'resolved_count':    resolved_count,
        'unique_ips':        unique_ips,
        'severity_summary':  severity_summary,

        # Tables
        'top_attacking_ips': top_attacking_ips,
        'top_traffic_ips':   top_traffic_ips,

        # Paginated datasets
        'page_obj':          page_obj,
        'traffic_page_obj':  traffic_page_obj,
        'active_tab':        active_tab,
        
        # IP Reputation maps for template
        'blocked_ips':       blocked_ips,
        'alerted_ips':       alerted_ips,

        'report_generated_at': timezone.now(),
    }
    return render(request, 'reports/reports.html', context)



# ─────────────────────────────────────────────────────────────────────────────
# CSV Exports
# ─────────────────────────────────────────────────────────────────────────────

@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Traffic exports are limited to Administrators and Security Analysts.')
def export_traffic_csv(request):
    """
    Exports all (filtered) traffic logs as a CSV file download.
    Uses Python's built-in csv module — no additional dependencies required.
    """
    traffic_qs, _, filters = _get_filtered_querysets(request)

    response = HttpResponse(content_type='text/csv')
    filename = f"netwatch_traffic_report.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)

    # Header row
    writer.writerow([
        'IP Address', 'URL Accessed', 'Request Method', 'Timestamp (UTC)'
    ])

    # Data rows — ordered by timestamp descending (newest first)
    for log in traffic_qs.order_by('-timestamp'):
        writer.writerow([
            log.ip_address,
            log.url_accessed,
            log.request_method,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        ])

    return response


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Alert exports are limited to Administrators and Security Analysts.')
def export_alerts_csv(request):
    """
    Exports all (filtered) DDoS alerts as a CSV file download.
    Includes Detection Type column so exported reports show which engine fired.
    """
    _, alerts_qs, filters = _get_filtered_querysets(request)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="netwatch_ddos_alerts.csv"'

    writer = csv.writer(response)
    # Detection Type column added between Severity and Message
    writer.writerow([
        'ID', 'IP Address', 'Request Count', 'Severity',
        'Detection Type', 'Message', 'Detected At (UTC)', 'Status'
    ])

    for alert in alerts_qs.order_by('-timestamp'):
        writer.writerow([
            alert.id,
            alert.ip_address,
            alert.request_count,
            alert.get_severity_display(),
            # get_detection_type_display() returns the human-readable label
            # from DETECTION_TYPE_CHOICES (e.g. "Traffic Spike")
            alert.get_detection_type_display(),
            alert.message,
            alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'Resolved' if alert.resolved else 'Active',
        ])

    return response


# ─────────────────────────────────────────────────────────────────────────────
# PDF Exports (uses reportlab)
# ─────────────────────────────────────────────────────────────────────────────

def _build_pdf_header(elements, styles, title, subtitle):
    """
    Helper: appends a styled header block to a reportlab elements list.
    Centralizes PDF branding so both traffic and alert PDFs look consistent.
    """
    from reportlab.platypus import Paragraph, Spacer, HRFlowable
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_LEFT

    title_style = ParagraphStyle(
        'NwTitle',
        parent=styles['Normal'],
        fontSize=20,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        'NwSub',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=2,
    )

    elements.append(Paragraph('🛡 NetWatch Security System', title_style))
    elements.append(Paragraph(title, ParagraphStyle(
        'NwTitle2', parent=styles['Normal'], fontSize=14,
        fontName='Helvetica-Bold', textColor=colors.HexColor('#1e3a5f'), spaceAfter=4,
    )))
    elements.append(Paragraph(subtitle, sub_style))
    elements.append(Paragraph(
        f'Generated: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")} UTC',
        sub_style
    ))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(HRFlowable(width="100%", thickness=1.5,
        color=colors.HexColor('#1e3a5f'), spaceAfter=12))


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Traffic exports are limited to Administrators and Security Analysts.')
def export_traffic_pdf(request):
    """
    Generates a professionally formatted PDF Traffic Report using reportlab.
    Limited to 500 most recent records to keep the file size manageable.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        )

        traffic_qs, _, filters = _get_filtered_querysets(request)
        traffic_qs = traffic_qs.order_by('-timestamp')[:500]

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=0.75*inch, rightMargin=0.75*inch,
            topMargin=0.75*inch, bottomMargin=0.75*inch,
        )
        elements = []
        styles = getSampleStyleSheet()

        _build_pdf_header(
            elements, styles,
            'Traffic Activity Report',
            f'Date Range: {filters["date_from"] or "All time"} → {filters["date_to"] or "Present"}'
        )

        # Summary line
        from reportlab.platypus import Paragraph as P
        elements.append(P(
            f'Total Records: <b>{traffic_qs.count()}</b>',
            getSampleStyleSheet()['Normal']
        ))
        elements.append(Spacer(1, 0.15*inch))

        # Table
        data = [['IP Address', 'URL Accessed', 'Method', 'Timestamp (UTC)']]
        for log in traffic_qs:
            url = log.url_accessed
            url = url[:55] + '…' if len(url) > 55 else url
            data.append([
                log.ip_address,
                url,
                log.request_method,
                log.timestamp.strftime('%Y-%m-%d %H:%M'),
            ])

        table = Table(
            data,
            colWidths=[1.5*inch, 3.0*inch, 0.8*inch, 1.7*inch],
            repeatRows=1,   # Repeat header row on each PDF page
        )
        table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
            ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (-1, 0), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f0f5ff')]),
            ('FONTSIZE',     (0, 1), (-1, -1), 7.5),
            ('GRID',         (0, 0), (-1, -1), 0.4, colors.HexColor('#d1dae8')),
            ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',   (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
        ]))
        elements.append(table)

        doc.build(elements)
        buffer.seek(0)

        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="netwatch_traffic_report.pdf"'
        return response

    except ImportError:
        return HttpResponse(
            'reportlab not installed. Run: pip install reportlab',
            status=500
        )


@role_required('admin', 'analyst', redirect_url='dashboard', message='Access Denied: Alert exports are limited to Administrators and Security Analysts.')
def export_alerts_pdf(request):
    """
    Generates a professionally formatted PDF DDoS Incident Report using reportlab.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        )

        _, alerts_qs, filters = _get_filtered_querysets(request)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=0.75*inch, rightMargin=0.75*inch,
            topMargin=0.75*inch, bottomMargin=0.75*inch,
        )
        elements = []
        styles = getSampleStyleSheet()

        _build_pdf_header(
            elements, styles,
            'DDoS Incident Report',
            f'Date Range: {filters["date_from"] or "All time"} → {filters["date_to"] or "Present"}'
        )

        # Summary line
        elements.append(Paragraph(
            f'Total: <b>{alerts_qs.count()}</b> | '
            f'Active: <b>{alerts_qs.filter(resolved=False).count()}</b> | '
            f'Critical: <b>{alerts_qs.filter(severity="critical").count()}</b>',
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.15*inch))

        data = [['#', 'IP Address', 'Req/Min', 'Severity', 'Detection Type', 'Detected At', 'Status']]
        sev_color = {
            'critical': colors.HexColor('#fee2e2'),
            'high':     colors.HexColor('#ffedd5'),
            'medium':   colors.HexColor('#fef9c3'),
            'low':      colors.HexColor('#e0f2fe'),
        }

        row_colors = []
        for i, alert in enumerate(alerts_qs.order_by('-timestamp'), start=1):
            data.append([
                str(alert.id),
                alert.ip_address,
                str(alert.request_count),
                alert.get_severity_display(),
                # Human-readable detection type (e.g. "Traffic Spike")
                alert.get_detection_type_display(),
                alert.timestamp.strftime('%Y-%m-%d %H:%M'),
                'Resolved' if alert.resolved else 'ACTIVE',
            ])
            row_colors.append(sev_color.get(alert.severity, colors.white))

        table = Table(
            data,
            # Adjusted column widths to fit 7 columns on A4 (usable ≈ 7 inches)
            colWidths=[0.4*inch, 1.4*inch, 0.6*inch, 0.8*inch, 1.2*inch, 1.4*inch, 0.7*inch],
            repeatRows=1,
        )

        style_cmds = [
            ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
            ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (-1, 0), 9),
            ('FONTSIZE',     (0, 1), (-1, -1), 7.5),
            ('GRID',         (0, 0), (-1, -1), 0.4, colors.HexColor('#d1dae8')),
            ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',   (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
        ]
        # Apply per-row severity background colors
        for row_idx, color in enumerate(row_colors, start=1):
            style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), color))

        table.setStyle(TableStyle(style_cmds))
        elements.append(table)

        doc.build(elements)
        buffer.seek(0)

        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="netwatch_ddos_report.pdf"'
        return response

    except ImportError:
        return HttpResponse(
            'reportlab not installed. Run: pip install reportlab',
            status=500
        )
