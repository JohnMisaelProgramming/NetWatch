from django.urls import path
from accounts.views import login_view, logout_view, profile_view, change_password_view

urlpatterns = [
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),
    path('profile/change-password/', change_password_view, name='change_password'),
]