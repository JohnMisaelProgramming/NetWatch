from django.db import models

class TrafficLog(models.Model):
    ip_address = models.CharField(max_length=100, db_index=True)  # Supports both IPv4 and IPv6, indexed for speed
    url_accessed = models.CharField(max_length=255)
    request_method = models.CharField(max_length=10)  # e.g., GET, POST
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)  # Indexed for time-window scans

    def __str__(self):
        return f"{self.ip_address} - {self.url_accessed}"
