"""
URL configuration for netwatch project.

URL Structure:
  /               → dashboard (home)
  /analytics/     → Step 8 — Traffic Visualization
  /analytics/data/→ Step 8 — JSON API for Chart.js
  /alerts/        → Step 9 — Alert Management List
  /alerts/<id>/   → Step 9 — Alert Detail
  /alerts/<id>/resolve/ → Step 9 — Resolve Action
  /reports/       → Step 10 — Reports & Audit
  /reports/export/... → Step 10 — CSV/PDF Downloads
  /login/         → Authentication
  /logout/        → Authentication
  /admin/         → Django Admin
"""
from django.contrib import admin
from django.urls import path, include

from dashboard.views import dashboard_data
from traffic.ingest_api import ingest_traffic   # External traffic ingest API

urlpatterns = [
    path('admin/', admin.site.urls),

    # REST API for external application traffic ingestion ──
    # ShopSafe (Target App) sends traffic metadata here via POST.
    # This must be registered BEFORE the catch-all includes below.
    path('api/ingest/', ingest_traffic, name='api_ingest'),

    path('dashboard/data/', dashboard_data, name='dashboard_data'),
    path('', include('dashboard.urls')),   # Dashboard + Analytics
    path('', include('accounts.urls')),    # Login / Logout
    path('', include('alerts.urls')),      # Alert Management
    path('', include('reports.urls')),     # Reports & Audit
]
