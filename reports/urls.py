from django.urls import path
from . import views

urlpatterns = [
    path('reports/', views.reports_home, name='reports'),
    path('reports/export/traffic/csv/', views.export_traffic_csv, name='export_traffic_csv'),
    path('reports/export/alerts/csv/',  views.export_alerts_csv,  name='export_alerts_csv'),
    path('reports/export/traffic/pdf/', views.export_traffic_pdf, name='export_traffic_pdf'),
    path('reports/export/alerts/pdf/',  views.export_alerts_pdf,  name='export_alerts_pdf'),
]
