from django.urls import path

from identity.views import callback, login, logout

urlpatterns = [
    path("login", login, name="kinde-login"),
    path("callback", callback, name="kinde-callback"),
    path("logout", logout, name="kinde-logout"),
]
