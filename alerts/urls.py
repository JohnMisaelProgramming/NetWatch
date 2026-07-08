from django.urls import path
from alerts import views

urlpatterns = [
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('alerts/<int:pk>/', views.alert_detail, name='alert_detail'),
    path('alerts/<int:pk>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('alerts/<int:pk>/reopen/', views.reopen_alert, name='reopen_alert'),
    path('alerts/<int:pk>/note/', views.add_alert_note, name='add_alert_note'),
    path('alerts/bulk-resolve/', views.bulk_resolve_alerts, name='bulk_resolve_alerts'),
    path('rate-limits/', views.rate_limit_history, name='rate_limit_history'),
    path('settings/', views.settings_view, name='settings'),
    path('blocklist/', views.blocklist_view, name='blocklist'),
    path('blocklist/add/', views.blocklist_add_ip, name='blocklist_add_ip'),
    path('alerts/<int:pk>/block/', views.block_ip, name='block_ip'),
    path('blocklist/<int:pk>/unblock/', views.unblock_ip, name='unblock_ip'),
    path('blocklist/unblock-by-ip/<path:ip_address>/', views.unblock_ip_by_ip, name='unblock_ip_by_ip'),
    path('simulation/', views.simulation_lab, name='simulation_lab'),
    path('simulation/start/', views.start_simulation, name='start_simulation'),
    path('simulation/stop/<int:pk>/', views.stop_simulation, name='stop_simulation'),
    path('simulation/status/', views.simulation_status_api, name='simulation_status_api'),
    path('investigate/', views.ip_investigation, name='ip_investigation'),
    path('investigate/export/csv/', views.export_investigation_csv, name='export_investigation_csv'),
    path('settings/whitelist/add/', views.whitelist_add_ip, name='whitelist_add_ip'),
    path('settings/whitelist/<int:pk>/delete/', views.whitelist_delete_ip, name='whitelist_delete_ip'),
    path('audit-log/', views.audit_log_view, name='audit_log'),
]
