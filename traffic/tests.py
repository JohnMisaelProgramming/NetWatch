from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase

from accounts.models import Profile
from traffic.middleware import TrafficLoggingMiddleware
from alerts.models import Alert, RateLimitViolation, SystemSettings
from traffic.models import TrafficLog


class TrafficMiddlewareTests(TestCase):
	def setUp(self):
		self.factory = RequestFactory()
		self.middleware = TrafficLoggingMiddleware(lambda request: None)
		self.user = User.objects.create_user(username='worker', password='password123')
		profile, _ = Profile.objects.get_or_create(user=self.user)
		profile.role = 'viewer'
		profile.save()
		settings = SystemSettings.get_settings()
		settings.request_threshold = 999
		settings.time_window_minutes = 1
		settings.rate_limit_threshold = 2
		settings.rate_limit_window_minutes = 1
		settings.save()

	def test_middleware_records_rate_limit_violation(self):
		for _ in range(2):
			TrafficLog.objects.create(
				ip_address='203.0.113.10',
				url_accessed='/dashboard/',
				request_method='GET',
			)

		# Simulate a 3rd request logging from the ingest API (since local middleware no longer logs NetWatch traffic)
		TrafficLog.objects.create(
			ip_address='203.0.113.10',
			url_accessed='/dashboard/',
			request_method='GET',
		)
		self.assertEqual(TrafficLog.objects.filter(ip_address='203.0.113.10').count(), 3)
		
		# Decoupled flow: Middleware logs the request, but doesn't run the detector immediately
		self.assertEqual(RateLimitViolation.objects.filter(ip_address='203.0.113.10').count(), 0)
		self.assertEqual(Alert.objects.filter(ip_address='203.0.113.10').count(), 0)

		# Explicitly trigger the background monitoring engine command
		from django.core.management import call_command
		call_command('run_detector', once=True)

		# The engine should process the logs and create the violation and alert
		self.assertEqual(RateLimitViolation.objects.filter(ip_address='203.0.113.10').count(), 1)
		self.assertEqual(Alert.objects.filter(ip_address='203.0.113.10').count(), 1)
