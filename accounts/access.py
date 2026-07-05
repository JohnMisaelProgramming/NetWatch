from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect


def get_user_role(user):
    if not getattr(user, 'is_authenticated', False):
        return None

    profile = getattr(user, 'profile', None)
    return getattr(profile, 'role', None)


def role_required(*allowed_roles, redirect_url='dashboard', message='Access denied.'):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path(), settings.LOGIN_URL)

            role = get_user_role(request.user)
            if role not in allowed_roles:
                messages.error(request, message)
                return redirect(redirect_url)

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator