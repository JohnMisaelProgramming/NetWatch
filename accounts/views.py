from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.contrib.auth.models import User  # type: ignore

from accounts.access import get_user_role


def login_view(request):
    error = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Support logging in via email
        if username and '@' in username:
            try:
                user_obj = User.objects.get(email__iexact=username)  # type: ignore
                username = user_obj.username
            except User.DoesNotExist:
                pass

        user = authenticate(
            request,
            username=username,
            password=password
        )
        if user is not None:

            login(request, user)
            return redirect('dashboard')
        else:
            error = "Invalid username or password. Please try again."
        
    return render(
        request, 
        'accounts/login.html',
        {'error': error}
    )


@require_POST
def logout_view(request):
    """
    Logout requires POST to prevent CSRF-like attacks via GET requests
    (e.g., an attacker embedding <img src="/logout/"> in a page).
    """
    logout(request)
    return redirect('login')


@login_required
def profile_view(request):
    """
    User profile page showing account details and role information,
    supporting profile details and avatar image updates.
    """
    profile = getattr(request.user, 'profile', None)
    if not profile:
        from accounts.models import Profile
        profile = Profile.objects.create(user=request.user)  # type: ignore

    if request.method == 'POST':
        # Get POST fields
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        bio = request.POST.get('bio', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        department = request.POST.get('department', '').strip()
        title = request.POST.get('title', '').strip()
        avatar = request.FILES.get('avatar')

        # Update User fields
        request.user.first_name = first_name
        request.user.last_name = last_name
        request.user.email = email
        request.user.save()

        # Update Profile fields
        profile.bio = bio
        profile.phone_number = phone_number
        profile.department = department
        profile.title = title
        if avatar:
            profile.avatar = avatar
        profile.save()

        # Add to Audit Log
        from alerts.models import AuditLog
        AuditLog.objects.create(  # type: ignore
            user=request.user,
            action='update_settings',
            target=f"Profile: {request.user.username}",
            details=f"Updated name, email, contact info, and profile details."
        )

        messages.success(request, 'Your profile details have been updated successfully.')
        return redirect('profile')

    user_role = get_user_role(request.user)
    context = {
        'profile': profile,
        'user_role': user_role,
    }
    return render(request, 'accounts/profile.html', context)


@login_required
def change_password_view(request):
    """
    Password change view using Django's built-in PasswordChangeForm.
    Maintains the session after password change so the user isn't logged out.
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keep user logged in

            # Create audit log entry
            from alerts.models import AuditLog
            AuditLog.objects.create(  # type: ignore
                user=request.user,
                action='change_password',
                target=request.user.username,
                details='Password changed successfully via profile page',
            )

            messages.success(request, 'Your password has been changed successfully.')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'accounts/change_password.html', {'form': form})