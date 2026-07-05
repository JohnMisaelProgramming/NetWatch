from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout

def login_view(request):
    error = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate (
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

def logout_view(request):
    logout(request)
    return redirect('login')