from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from accounts.models import Profile
from .models import Alert, IPBlocklist, RateLimitViolation, SystemSettings, SimulationRun, IPWhitelist
from traffic.models import TrafficLog


def create_user(username, role):
	user = User.objects.create_user(username=username, password='password123')
	profile, _ = Profile.objects.get_or_create(user=user)
	profile.role = role
	profile.save()
	return user


class AccessControlTests(TestCase):
	def setUp(self):
		self.admin = create_user('admin_user', 'admin')
		self.analyst = create_user('analyst_user', 'analyst')
		self.viewer = create_user('viewer_user', 'viewer')

	def test_viewer_is_redirected_from_restricted_routes(self):
		self.client.force_login(self.viewer)

		restricted_urls = [
			reverse('alerts_list'),
			reverse('analytics'),
			reverse('analytics_data'),
			reverse('reports'),
			reverse('rate_limit_history'),
			reverse('settings'),
			reverse('blocklist'),
		]

		for url in restricted_urls:
			response = self.client.get(url)
			self.assertEqual(response.status_code, 302)
			self.assertEqual(response.url, reverse('dashboard'))

	def test_analyst_can_review_rate_limits_but_not_admin_settings(self):
		self.client.force_login(self.analyst)

		response = self.client.get(reverse('rate_limit_history'))
		self.assertEqual(response.status_code, 200)

		response = self.client.get(reverse('settings'))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('dashboard'))

	def test_admin_can_access_blocklist_and_settings(self):
		self.client.force_login(self.admin)

		response = self.client.get(reverse('settings'))
		self.assertEqual(response.status_code, 200)

		response = self.client.get(reverse('blocklist'))
		self.assertEqual(response.status_code, 200)


class RateLimitHistoryViewTests(TestCase):
	def setUp(self):
		self.admin = create_user('history_admin', 'admin')

	def test_rate_limit_history_shows_violation_records(self):
		RateLimitViolation.objects.create(
			ip_address='10.10.10.10',
			request_count=42,
			threshold=30,
			window_minutes=1,
			path='/login/',
			request_method='GET',
			message='Rate-limit violation detected from IP 10.10.10.10.',
		)

		self.client.force_login(self.admin)
		response = self.client.get(reverse('rate_limit_history'))

		self.assertContains(response, '10.10.10.10')
		self.assertContains(response, '42')


class SidebarVisibilityTests(TestCase):
	def setUp(self):
		self.admin = create_user('sidebar_admin', 'admin')
		self.viewer = create_user('sidebar_viewer', 'viewer')

	def test_viewer_sidebar_hides_privileged_links(self):
		self.client.force_login(self.viewer)
		response = self.client.get(reverse('dashboard'))

		self.assertNotContains(response, 'href="/alerts/"')
		self.assertNotContains(response, 'href="/analytics/"')
		self.assertNotContains(response, 'href="/rate-limits/"')
		self.assertNotContains(response, 'href="/reports/"')
		self.assertNotContains(response, 'href="/settings/"')
		self.assertNotContains(response, 'href="/blocklist/"')
		self.assertNotContains(response, 'href="/admin/"')

	def test_admin_sidebar_shows_privileged_links(self):
		self.client.force_login(self.admin)
		response = self.client.get(reverse('dashboard'))

		self.assertContains(response, 'href="/alerts/"')
		self.assertContains(response, 'href="/analytics/"')
		self.assertContains(response, 'href="/rate-limits/"')
		self.assertContains(response, 'href="/reports/"')
		self.assertContains(response, 'href="/settings/"')
		self.assertContains(response, 'href="/blocklist/"')
		self.assertContains(response, 'href="/admin/"')


class AlertDetectionTypeFilteringTests(TestCase):
	def setUp(self):
		self.admin = create_user('filter_admin', 'admin')
		
		# Create some alerts of different detection types
		self.alert_spike = Alert.objects.create(
			ip_address='192.168.10.10',
			request_count=15,
			severity=Alert.SEVERITY_HIGH,
			detection_type=Alert.DETECTION_SPIKE,
			message='Traffic spike detected'
		)
		self.alert_rate = Alert.objects.create(
			ip_address='192.168.20.20',
			request_count=45,
			severity=Alert.SEVERITY_CRITICAL,
			detection_type=Alert.DETECTION_RATE_LIMIT,
			message='Rate limit violation'
		)
		self.alert_manual = Alert.objects.create(
			ip_address='192.168.30.30',
			request_count=1,
			severity=Alert.SEVERITY_LOW,
			detection_type=Alert.DETECTION_MANUAL,
			message='Manual alert'
		)

	def test_alerts_list_filters_by_detection_type(self):
		self.client.force_login(self.admin)
		
		# Test filter by traffic_spike
		response = self.client.get(reverse('alerts_list'), {'detection_type': 'traffic_spike'})
		self.assertContains(response, '192.168.10.10')
		self.assertNotContains(response, '192.168.20.20')
		self.assertNotContains(response, '192.168.30.30')
		
		# Test filter by rate_limit
		response = self.client.get(reverse('alerts_list'), {'detection_type': 'rate_limit'})
		self.assertNotContains(response, '192.168.10.10')
		self.assertContains(response, '192.168.20.20')
		self.assertNotContains(response, '192.168.30.30')

	def test_reports_filters_by_detection_type(self):
		self.client.force_login(self.admin)
		
		# Test filter by traffic_spike
		response = self.client.get(reverse('reports'), {'detection_type': 'traffic_spike'})
		self.assertContains(response, '192.168.10.10')
		self.assertNotContains(response, '192.168.20.20')
		self.assertNotContains(response, '192.168.30.30')
		
		# Test filter by rate_limit
		response = self.client.get(reverse('reports'), {'detection_type': 'rate_limit'})
		self.assertNotContains(response, '192.168.10.10')
		self.assertContains(response, '192.168.20.20')
		self.assertNotContains(response, '192.168.30.30')


class ThreatSeverityAlgorithmTests(TestCase):
	def setUp(self):
		self.settings = SystemSettings.get_settings()

	def test_get_severity_uses_settings_thresholds(self):
		from .detector import get_severity
		# Default thresholds: Medium=20, High=50, Critical=100
		self.assertEqual(get_severity(10, self.settings), Alert.SEVERITY_LOW)
		self.assertEqual(get_severity(25, self.settings), Alert.SEVERITY_MEDIUM)
		self.assertEqual(get_severity(75, self.settings), Alert.SEVERITY_HIGH)
		self.assertEqual(get_severity(120, self.settings), Alert.SEVERITY_CRITICAL)

		# Modify thresholds
		self.settings.severity_medium_threshold = 5
		self.settings.severity_high_threshold = 10
		self.settings.severity_critical_threshold = 15
		self.settings.save()

		# Assert severity levels shift accordingly
		self.assertEqual(get_severity(4, self.settings), Alert.SEVERITY_LOW)
		self.assertEqual(get_severity(6, self.settings), Alert.SEVERITY_MEDIUM)
		self.assertEqual(get_severity(11, self.settings), Alert.SEVERITY_HIGH)
		self.assertEqual(get_severity(16, self.settings), Alert.SEVERITY_CRITICAL)

	def test_get_rate_limit_severity_uses_settings_multipliers(self):
		from .detector import get_rate_limit_severity
		threshold = 10
		# Default multipliers: High=2.0, Critical=4.0
		# Medium if >= threshold (10), High if >= 20, Critical if >= 40
		self.assertEqual(get_rate_limit_severity(15, threshold, self.settings), Alert.SEVERITY_MEDIUM)
		self.assertEqual(get_rate_limit_severity(25, threshold, self.settings), Alert.SEVERITY_HIGH)
		self.assertEqual(get_rate_limit_severity(45, threshold, self.settings), Alert.SEVERITY_CRITICAL)

		# Modify multipliers
		self.settings.rate_limit_high_multiplier = 1.5
		self.settings.rate_limit_critical_multiplier = 3.0
		self.settings.save()

		# High if >= 15, Critical if >= 30
		self.assertEqual(get_rate_limit_severity(12, threshold, self.settings), Alert.SEVERITY_MEDIUM)
		self.assertEqual(get_rate_limit_severity(18, threshold, self.settings), Alert.SEVERITY_HIGH)
		self.assertEqual(get_rate_limit_severity(35, threshold, self.settings), Alert.SEVERITY_CRITICAL)


class ReportsAndAnalyticsEnhancementTests(TestCase):
	def setUp(self):
		from traffic.models import TrafficLog
		self.admin = create_user('reports_admin', 'admin')
		TrafficLog.objects.create(ip_address='192.168.99.1', url_accessed='/home/', request_method='GET')
		TrafficLog.objects.create(ip_address='192.168.99.2', url_accessed='/admin/', request_method='POST')
		TrafficLog.objects.create(ip_address='10.0.0.1', url_accessed='/api/', request_method='GET')

	def test_reports_traffic_tab_displays_logs(self):
		self.client.force_login(self.admin)
		
		# Test fetching the traffic logs tab
		response = self.client.get(reverse('reports'), {'tab': 'traffic'})
		self.assertContains(response, '192.168.99.1')
		self.assertContains(response, '192.168.99.2')
		self.assertContains(response, '10.0.0.1')
		
		# Test filtering by request_method = POST
		response = self.client.get(reverse('reports'), {'tab': 'traffic', 'request_method': 'POST'})
		self.assertNotContains(response, '192.168.99.1') # GET
		self.assertContains(response, '192.168.99.2') # POST
		self.assertNotContains(response, '10.0.0.1') # GET

		# Test filtering by IP
		response = self.client.get(reverse('reports'), {'tab': 'traffic', 'ip_address': '192.168.99'})
		self.assertContains(response, '192.168.99.1')
		self.assertContains(response, '192.168.99.2')
		self.assertNotContains(response, '10.0.0.1')

	def test_analytics_data_filters_charts_correctly(self):
		self.client.force_login(self.admin)
		
		# Unfiltered analytics data (excludes the GET request to analytics_data ignored by middleware)
		response = self.client.get(reverse('analytics_data'))
		self.assertEqual(response.status_code, 200)
		data = response.json()
		self.assertEqual(data['total_requests'], 3)
		
		# Filter by IP address
		response = self.client.get(reverse('analytics_data'), {'ip_address': '192.168.99'})
		data = response.json()
		self.assertEqual(data['total_requests'], 2)
		
		# Filter by request method
		response = self.client.get(reverse('analytics_data'), {'request_method': 'POST'})
		data = response.json()
		self.assertEqual(data['total_requests'], 1)


class AutomaticIPBlockingTests(TestCase):
	def setUp(self):
		self.settings = SystemSettings.get_settings()
		self.admin = create_user('settings_admin', 'admin')
		self.client.force_login(self.admin)

	def test_settings_save_auto_block_configuration(self):
		# Update settings view POST with auto-blocking config
		response = self.client.post(reverse('settings'), {
			'request_threshold': 5,
			'time_window_minutes': 1,
			'rate_limit_threshold': 30,
			'rate_limit_window_minutes': 1,
			'severity_medium_threshold': 20,
			'severity_high_threshold': 50,
			'severity_critical_threshold': 100,
			'rate_limit_high_multiplier': 2.0,
			'rate_limit_critical_multiplier': 4.0,
			'enable_auto_blocking': 'on',
			'auto_block_threshold': 10
		})
		self.assertEqual(response.status_code, 302)
		
		# Verify db updated
		self.settings.refresh_from_db()
		self.assertTrue(self.settings.enable_auto_blocking)
		self.assertEqual(self.settings.auto_block_threshold, 10)

	def test_auto_blocking_disabled_by_default(self):
		from traffic.models import TrafficLog
		from .detector import detect_ddos
		
		# Keep enable_auto_blocking False
		self.settings.enable_auto_blocking = False
		self.settings.request_threshold = 2
		self.settings.auto_block_threshold = 3
		self.settings.save()

		# Create traffic exceeding the threshold
		ip = '10.20.30.40'
		for _ in range(4):
			TrafficLog.objects.create(ip_address=ip, url_accessed='/', request_method='GET')
		
		# Run detection
		detect_ddos(ip)

		# Check blocklist: should be empty
		self.assertFalse(IPBlocklist.objects.filter(ip_address=ip).exists())

	def test_auto_blocking_triggers_when_enabled(self):
		from traffic.models import TrafficLog
		from .detector import detect_ddos
		
		# Enable auto-blocking, set threshold
		self.settings.enable_auto_blocking = True
		self.settings.request_threshold = 2
		self.settings.auto_block_threshold = 3
		self.settings.save()

		# Create traffic exceeding the threshold (4 requests)
		ip = '10.20.30.50'
		for _ in range(4):
			TrafficLog.objects.create(ip_address=ip, url_accessed='/', request_method='GET')
		
		# Run detection
		detect_ddos(ip)

		# Check blocklist: IP should be added
		self.assertTrue(IPBlocklist.objects.filter(ip_address=ip).exists())
		blocked = IPBlocklist.objects.get(ip_address=ip)
		self.assertIn("Automatically blocked", blocked.reason)
		self.assertIsNone(blocked.added_by)

	def test_middleware_blocks_auto_blocked_ip(self):
		# Programmatically block an IP
		ip = '10.20.30.60'
		IPBlocklist.objects.create(
			ip_address=ip,
			reason="Automatically blocked: threshold exceeded",
			added_by=None
		)

		# Try to make a request using the client with this IP
		response = self.client.get(reverse('dashboard'), REMOTE_ADDR=ip)
		self.assertEqual(response.status_code, 403)
		self.assertIn("Your IP address has been blocked", response.content.decode())


class SimulationValidationLabTests(TestCase):
	def setUp(self):
		self.admin = create_user('sim_admin', 'admin')
		self.analyst = create_user('sim_analyst', 'analyst')
		self.viewer = create_user('sim_viewer', 'viewer')

	def test_access_controls_on_simulation_endpoints(self):
		# Viewer should be blocked
		self.client.force_login(self.viewer)
		response = self.client.get(reverse('simulation_lab'))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('dashboard'))

		# Analyst should be blocked
		self.client.force_login(self.analyst)
		response = self.client.get(reverse('simulation_lab'))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('dashboard'))

		# Admin should be allowed
		self.client.force_login(self.admin)
		response = self.client.get(reverse('simulation_lab'))
		self.assertEqual(response.status_code, 200)

	def test_middleware_extracts_simulated_ip(self):
		# Send a request with simulated IP header
		simulated_ip = '8.8.8.8'
		self.client.force_login(self.viewer)
		response = self.client.get(reverse('dashboard'), HTTP_X_NETWATCH_SIMULATED_IP=simulated_ip)
		
		# Confirm a TrafficLog was created with the simulated IP
		from traffic.models import TrafficLog
		self.assertTrue(TrafficLog.objects.filter(ip_address=simulated_ip).exists())

	def test_start_simulation_endpoint(self):
		self.client.force_login(self.admin)
		
		# Trigger start action
		response = self.client.post(reverse('start_simulation'), {
			'attack_type': 'rate_limit',
			'target_endpoint': '/dashboard/',
			'num_requests': 50,
			'delay_ms': 0,
			'simulated_ips_count': 1,
		})
		
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('simulation_lab'))
		
		# Confirm model was created
		run = SimulationRun.objects.first()
		self.assertIsNotNone(run)
		self.assertEqual(run.attack_type, 'rate_limit')
		self.assertEqual(run.target_endpoint, '/dashboard/')
		self.assertEqual(run.num_requests, 50)
		self.assertEqual(run.simulated_ips_count, 1)


class InvestigationCenterTests(TestCase):
	def setUp(self):
		self.admin = create_user('invest_admin', 'admin')
		self.analyst = create_user('invest_analyst', 'analyst')
		self.viewer = create_user('invest_viewer', 'viewer')

	def test_access_controls_on_investigation_center(self):
		# Viewer should be blocked
		self.client.force_login(self.viewer)
		response = self.client.get(reverse('ip_investigation'))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('dashboard'))

		# Analyst should be allowed
		self.client.force_login(self.analyst)
		response = self.client.get(reverse('ip_investigation'))
		self.assertEqual(response.status_code, 200)

		# Admin should be allowed
		self.client.force_login(self.admin)
		response = self.client.get(reverse('ip_investigation'))
		self.assertEqual(response.status_code, 200)

	def test_global_timeline_mode_queries(self):
		# Setup an alert and violation
		Alert.objects.create(
			ip_address='192.168.5.5',
			request_count=50,
			severity='critical',
			detection_type='traffic_spike',
			message='Global test alert',
		)
		RateLimitViolation.objects.create(
			ip_address='192.168.5.6',
			request_count=20,
			threshold=10,
			window_minutes=1,
			path='/api/',
			request_method='POST',
			message='Global test violation',
		)
		self.client.force_login(self.analyst)
		response = self.client.get(reverse('ip_investigation'))
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'Global test alert')
		self.assertContains(response, 'Global test violation')
		self.assertContains(response, '192.168.5.5')
		self.assertContains(response, '192.168.5.6')

	def test_ip_dossier_mode_queries(self):
		ip = '10.99.88.77'
		# Setup logs, alerts, and violations for this IP
		TrafficLog.objects.create(ip_address=ip, url_accessed='/login/', request_method='POST')
		TrafficLog.objects.create(ip_address=ip, url_accessed='/api/', request_method='GET')
		Alert.objects.create(
			ip_address=ip,
			request_count=35,
			severity='high',
			detection_type='traffic_spike',
			message='IP dossier test alert',
		)
		self.client.force_login(self.analyst)
		response = self.client.get(reverse('ip_investigation'), {'ip': ip})
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, ip)
		self.assertContains(response, 'IP dossier test alert')
		self.assertContains(response, '/login/')
		self.assertContains(response, '/api/')
		self.assertContains(response, 'HIGH Risk')


class AdministratorControlsTests(TestCase):
	def setUp(self):
		self.admin = create_user('admin_ctrl', 'admin')
		self.analyst = create_user('analyst_ctrl', 'analyst')
		self.viewer = create_user('viewer_ctrl', 'viewer')
		self.settings = SystemSettings.get_settings()

	def test_maintenance_mode_locks_out_viewer(self):
		# Enable maintenance mode
		self.settings.enable_maintenance_mode = True
		self.settings.save()

		# Viewer gets locked out with 503 status
		self.client.force_login(self.viewer)
		response = self.client.get(reverse('dashboard'))
		self.assertEqual(response.status_code, 503)
		self.assertContains(response, "System Under Maintenance", status_code=503)

		# Admin can bypass it and get 200 status
		self.client.force_login(self.admin)
		response = self.client.get(reverse('dashboard'))
		self.assertEqual(response.status_code, 200)

		# Disable maintenance mode
		self.settings.enable_maintenance_mode = False
		self.settings.save()

	def test_whitelist_bypasses_blocking_middleware(self):
		# Whitelist an IP
		IPWhitelist.objects.create(ip_address='123.123.123.123', reason='Test whitelist')
		# Add same IP to blocklist
		IPBlocklist.objects.create(ip_address='123.123.123.123', reason='Test block')

		# Access any page simulating this IP
		self.client.force_login(self.viewer)
		response = self.client.get(reverse('dashboard'), HTTP_X_NETWATCH_SIMULATED_IP='123.123.123.123')
		# Since it is whitelisted, the block list is bypassed and they get 200 OK
		self.assertEqual(response.status_code, 200)

	def test_whitelist_management_actions(self):
		self.client.force_login(self.admin)
		
		# Add IP to whitelist
		response = self.client.post(reverse('whitelist_add_ip'), {
			'ip_address': '9.9.9.9',
			'reason': 'Google DNS',
		})
		self.assertEqual(response.status_code, 302)
		self.assertTrue(IPWhitelist.objects.filter(ip_address='9.9.9.9').exists())

		# Delete from whitelist
		item = IPWhitelist.objects.get(ip_address='9.9.9.9')
		response = self.client.post(reverse('whitelist_delete_ip', args=[item.pk]))
		self.assertEqual(response.status_code, 302)
		self.assertFalse(IPWhitelist.objects.filter(ip_address='9.9.9.9').exists())
