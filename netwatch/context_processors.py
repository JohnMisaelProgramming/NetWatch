from alerts.models import Alert
from accounts.access import get_user_role


def netwatch_context(request):
    """
    Global template context processor for NetWatch.

    This function is called automatically on EVERY request by Django's
    template engine (configured in settings.py TEMPLATES > context_processors).

    What it does:
    - Injects 'active_alerts' count into ALL templates site-wide.
    - This is why the sidebar badge and topbar bell update on every page,
      not just the dashboard.

    Why a context processor instead of passing it in every view?
    - DRY principle (Don't Repeat Yourself)
    - If you add 10 more pages, you don't need to add active_alerts to 10 views
    - Changes to this logic automatically apply everywhere
    """
    if request.user.is_authenticated:
        active_alerts = Alert.objects.filter(resolved=False).count()
    else:
        active_alerts = 0

    user_role = get_user_role(request.user)

    return {
        'active_alerts': active_alerts,
        'user_role': user_role,
        'is_admin_user': user_role == 'admin',
        'is_analyst_user': user_role == 'analyst',
        'is_viewer_user': user_role == 'viewer',
    }
