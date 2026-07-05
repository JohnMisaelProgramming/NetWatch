from django.contrib import admin
from .models import Alert, RateLimitViolation, SystemSettings, IPBlocklist, IPWhitelist

admin.site.register(Alert)
admin.site.register(RateLimitViolation)
admin.site.register(SystemSettings)
admin.site.register(IPBlocklist)
admin.site.register(IPWhitelist)
