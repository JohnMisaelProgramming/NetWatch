from django.urls import path
from . import views

urlpatterns = [
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('alerts/<int:pk>/', views.alert_detail, name='alert_detail'),
    path('alerts/<int:pk>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('rate-limits/', views.rate_limit_history, name='rate_limit_history'),
    path('settings/', views.settings_view, name='settings'),
    path('blocklist/', views.blocklist_view, name='blocklist'),
    path('blocklist/add/', views.blocklist_add_ip, name='blocklist_add_ip'),
    path('alerts/<int:pk>/block/', views.block_ip, name='block_ip'),
    path('blocklist/<int:pk>/unblock/', views.unblock_ip, name='unblock_ip'),
    path('simulation/', views.simulation_lab, name='simulation_lab'),
    path('simulation/start/', views.start_simulation, name='start_simulation'),
    path('simulation/stop/<int:pk>/', views.stop_simulation, name='stop_simulation'),
    path('simulation/status/', views.simulation_status_api, name='simulation_status_api'),
    path('investigate/', views.ip_investigation, name='ip_investigation'),
    path('settings/whitelist/add/', views.whitelist_add_ip, name='whitelist_add_ip'),
    path('settings/whitelist/<int:pk>/delete/', views.whitelist_delete_ip, name='whitelist_delete_ip'),
]
