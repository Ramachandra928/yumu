"""Urls for apis"""

from .views import RecoverPasswordMailView
from .views import ResetPassword, RefreshToken
from .views import UserLogin, UserRegister, Logout, RecoverPassword

from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    url(r'^login', csrf_exempt(UserLogin.as_view())),
    url(r'^register', csrf_exempt(UserRegister.as_view())),
    url(r'^logout', csrf_exempt(Logout.as_view())),
    url(r'^refreshtoken/$', csrf_exempt(RefreshToken.as_view())),
    url(r'^recover/$', csrf_exempt(RecoverPassword.as_view()),
        name='password_reset_recover'),
    url(r'^recover/(?P<token>[\w:-]+)/mailview/$',
        csrf_exempt(RecoverPasswordMailView.as_view()),
        name='password_reset_webview'),
    url(r'^reset/(?P<token>[\w:-]+)/$',
        csrf_exempt(ResetPassword.as_view()),
        name='password_reset_reset'),
]
