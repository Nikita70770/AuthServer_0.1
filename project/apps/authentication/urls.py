from django.urls import path

from project.apps.authentication.views import refresh_token_view, login_view, get_user, logout_view

urlpatterns = [
    # path('token', access_token_view, name='access_token'),
    path('token/refresh', refresh_token_view, name="token_refresh"),
    path('user', get_user, name='user'),
    path('login', login_view, name='login'),
    path('logout', logout_view, name='logout'),
]
