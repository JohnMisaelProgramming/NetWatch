from django.urls import path
from .views import dashboard, analytics, analytics_data, dashboard_recent_stats, dashboard_data

urlpatterns = [
    path('', dashboard, name='dashboard'),
    path('data/', dashboard_data, name='dashboard_data'),
    path('recent-stats/', dashboard_recent_stats, name='dashboard_recent_stats'),
    path('analytics/', analytics, name='analytics'),
    path('analytics/data/', analytics_data, name='analytics_data'),
]
