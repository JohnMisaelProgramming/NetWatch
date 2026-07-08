"""
NetWatch Traffic Ingest API
============================
This module provides the REST API endpoint that external applications
(such as ShopSafe) use to forward their HTTP request metadata to NetWatch.

Architecture:
    External App (ShopSafe)  →  POST /api/ingest/  →  TrafficLog.create()
                                                         ↓
                                                   run_detector daemon
                                                         ↓
                                                   Alerts / Dashboard

Security:
    - Authenticated via a shared API key in the Authorization header.
    - Only accepts POST requests with JSON body.
    - Validates all required fields before creating a TrafficLog record.
    - CSRF is exempt because this is a machine-to-machine API, not a browser form.

Why this approach:
    By writing to the same TrafficLog model that the middleware uses,
    ALL existing detection, alerting, dashboard, analytics, and reporting
    features work without any modification. The detection engine doesn't
    care whether a TrafficLog came from the local middleware or from an
    external API call — it just processes TrafficLog records.
"""

import json
import logging

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from traffic.models import TrafficLog

logger = logging.getLogger(__name__)


@csrf_exempt      # Required: this is a machine-to-machine API, not a browser form
@require_POST     # Only accept POST requests; reject GET, PUT, DELETE, etc.
def ingest_traffic(request):
    """
    POST /api/ingest/
    
    Receives traffic log data from an external application and creates
    a TrafficLog record in NetWatch's database.

    Expected JSON body:
    {
        "ip_address":     "192.168.1.50",     (required) Client IP that made the request
        "url_accessed":   "/products/",        (required) The URL path that was accessed
        "request_method": "GET",               (required) HTTP method (GET, POST, etc.)
        "source":         "shopsafe"           (optional) Identifier for the source application
    }

    Headers:
        Authorization: Api-Key <NETWATCH_API_KEY>
        Content-Type: application/json

    Responses:
        201 Created   — Traffic log recorded successfully
        400 Bad Request — Missing required fields or invalid JSON
        403 Forbidden  — Invalid or missing API key
        405 Method Not Allowed — Non-POST request (handled by @require_POST)
    """

    # ── Step 1: API Key Authentication ──────────────────────────────────────
    # We check the Authorization header for a valid API key.
    # Format: "Api-Key <key>" (similar to how services like Datadog work)
    #
    # Why not use Django's built-in auth?
    # Because this is a server-to-server call, not a user login.
    # A simple API key is appropriate for a capstone project.
    # In production, you'd use OAuth2, mutual TLS, or JWT tokens.

    auth_header = request.META.get('HTTP_AUTHORIZATION', '')

    # Extract the key from "Api-Key <actual_key>"
    if not auth_header.startswith('Api-Key '):
        return JsonResponse(
            {'error': 'Missing or malformed Authorization header. Expected: Api-Key <key>'},
            status=403
        )

    provided_key = auth_header[len('Api-Key '):]    # Slice off the "Api-Key " prefix
    expected_key = getattr(settings, 'NETWATCH_API_KEY', None)

    if not expected_key or provided_key != expected_key:
        # Log the failed attempt for security auditing
        logger.warning(
            "Ingest API: rejected request with invalid API key from %s",
            request.META.get('REMOTE_ADDR', 'unknown')
        )
        return JsonResponse(
            {'error': 'Invalid API key.'},
            status=403
        )

    # ── Step 2: Parse JSON Body ─────────────────────────────────────────────
    # The request body must be valid JSON containing the traffic metadata.

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse(
            {'error': 'Invalid JSON body.'},
            status=400
        )

    # ── Step 3: Validate Required Fields ────────────────────────────────────
    # All three fields are mandatory — without them, the TrafficLog record
    # would be meaningless and could break downstream detection queries.

    ip_address = data.get('ip_address', '').strip()
    url_accessed = data.get('url_accessed', '').strip()
    request_method = data.get('request_method', '').strip().upper()
    source = data.get('source', 'external').strip()    # Optional metadata

    # Collect all missing fields to return a helpful error message
    missing_fields = []
    if not ip_address:
        missing_fields.append('ip_address')
    if not url_accessed:
        missing_fields.append('url_accessed')
    if not request_method:
        missing_fields.append('request_method')

    if missing_fields:
        return JsonResponse(
            {'error': f'Missing required fields: {", ".join(missing_fields)}'},
            status=400
        )

    # ── Step 4: Create the TrafficLog Record ────────────────────────────────
    # This is the same model that the local TrafficLoggingMiddleware writes to.
    # Once this record exists, the run_detector daemon will automatically
    # pick it up on its next detection pass and evaluate it for:
    #   - DDoS traffic spikes (detect_ddos)
    #   - Rate-limit violations (detect_rate_limit_violation)
    #   - Auto-blocking (check_and_perform_auto_block)
    #
    # No changes needed to the detection engine — it just queries TrafficLog.

    TrafficLog.objects.create(
        ip_address=ip_address,
        url_accessed=url_accessed,
        request_method=request_method,
    )

    # ── Step 5: Return Success ──────────────────────────────────────────────
    return JsonResponse(
        {
            'status': 'ok',
            'message': 'Traffic log recorded.',
            'source': source,
        },
        status=201    # 201 Created — standard HTTP status for resource creation
    )


@csrf_exempt
@require_POST
def ingest_event(request):
    """
    POST /api/events/
    
    Receives security events (failed logins, account lockouts, successful logins)
    from ShopSafe and records them in the NetWatch SecurityEvent database.
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')

    if not auth_header.startswith('Api-Key '):
        return JsonResponse(
            {'error': 'Missing or malformed Authorization header. Expected: Api-Key <key>'},
            status=403
        )

    provided_key = auth_header[len('Api-Key '):]
    expected_key = getattr(settings, 'NETWATCH_API_KEY', None)

    if not expected_key or provided_key != expected_key:
        logger.warning(
            "Event Ingest API: rejected request with invalid API key from %s",
            request.META.get('REMOTE_ADDR', 'unknown')
        )
        return JsonResponse(
            {'error': 'Invalid API key.'},
            status=403
        )

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse(
            {'error': 'Invalid JSON body.'},
            status=400
        )

    ip_address = data.get('ip_address', '').strip()
    event_type = data.get('event_type', '').strip()
    username = data.get('username', '').strip()
    details = data.get('details', '').strip()
    user_agent = data.get('user_agent', '').strip()
    source = data.get('source', 'external').strip()

    missing_fields = []
    if not ip_address:
        missing_fields.append('ip_address')
    if not event_type:
        missing_fields.append('event_type')

    if missing_fields:
        return JsonResponse(
            {'error': f'Missing required fields: {", ".join(missing_fields)}'},
            status=400
        )

    # Create the SecurityEvent record
    from alerts.models import SecurityEvent
    SecurityEvent.objects.create(
        ip_address=ip_address,
        event_type=event_type,
        username=username,
        details=details,
        user_agent=user_agent,
        source=source
    )

    return JsonResponse(
        {
            'status': 'ok',
            'message': 'Security event logged successfully.',
            'event_type': event_type,
        },
        status=201
    )

