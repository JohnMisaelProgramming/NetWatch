from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from accounts.models import Profile
from traffic.models import TrafficLog
from alerts.models import Alert

def create_user(username, role):
    user = User.objects.create_user(username=username, password='password123')
    profile, _ = Profile.objects.get_or_create(user=user)
    profile.role = role
    profile.save()
    return user

class ReportsAndExportsTests(TestCase):
    def setUp(self):
        self.admin = create_user('rep_admin', 'admin')
        self.analyst = create_user('rep_analyst', 'analyst')
        self.viewer = create_user('rep_viewer', 'viewer')

        # Create some traffic and alerts data
        TrafficLog.objects.create(ip_address='192.168.10.10', url_accessed='/home/', request_method='GET')
        Alert.objects.create(
            ip_address='192.168.10.11',
            request_count=45,
            severity='high',
            detection_type='traffic_spike',
            message='DDoS Threat Alert'
        )

    def test_reports_page_access_controls(self):
        # Viewer should be blocked
        self.client.force_login(self.viewer)
        response = self.client.get(reverse('reports'))
        self.assertEqual(response.status_code, 302)

        # Analyst should be allowed
        self.client.force_login(self.analyst)
        response = self.client.get(reverse('reports'))
        self.assertEqual(response.status_code, 200)

        # Admin should be allowed
        self.client.force_login(self.admin)
        response = self.client.get(reverse('reports'))
        self.assertEqual(response.status_code, 200)

    def test_traffic_csv_export(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse('export_traffic_csv'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn('attachment', response['Content-Disposition'])
        content = response.content.decode('utf-8')
        self.assertIn('IP Address', content)
        self.assertIn('192.168.10.10', content)

    def test_alerts_csv_export(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse('export_alerts_csv'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn('attachment', response['Content-Disposition'])
        content = response.content.decode('utf-8')
        self.assertIn('IP Address', content)
        self.assertIn('192.168.10.11', content)

    def test_traffic_pdf_export(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse('export_traffic_pdf'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])
        # A valid PDF starts with %PDF
        self.assertTrue(response.content.startswith(b'%PDF'))

    def test_alerts_pdf_export(self):
        self.client.force_login(self.analyst)
        response = self.client.get(reverse('export_alerts_pdf'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])
        # A valid PDF starts with %PDF
        self.assertTrue(response.content.startswith(b'%PDF'))
