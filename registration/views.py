'''Controller for Registration'''

# python imports
import os
import datetime
import logging

# local django Imports
from django.core import signing
from rest_framework import status
from django.template import loader
from django.contrib.auth import logout
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import render_to_response
from django.contrib.sites.models import RequestSite
from oauth2_provider.ext.rest_framework import TokenHasReadWriteScope

# application imports
from .models import AppUser
from .forms import PasswordResetForm
from .serializer import RegisterSerializer

from yumu.settings import LOGGING
from yumulogging.middleware import valiate_access_token
from yumuapi.utils.response_builder import get_response_json, get_error_json
from registration.middleware import time_zone_changer_for_request

from .middleware import get_user_data
from .middleware import save_location_settings
from .middleware import refresh_token, string_to_dict
from .middleware import make_user_response, get_error_message
from .middleware import send_email_on_recover_password, send_email_on_signup
from .login_response import make_login_response

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('django')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class UserRegister(APIView):

    """
    Register a user
    """

    def post(self, request):
        '''Defines post method in UserRegister view'''
        user_obj = None
        try:
            logger.info('Entered registration view')
            serializer = RegisterSerializer(data=request.DATA)
            if serializer.is_valid():
                logger.info('Saving the data using Register Serializer')
                user_obj = serializer.save()
                logger.info('Saving the password')
                user_obj.set_password(serializer.data['password'])
                user_obj.save()
                save_location_settings(user_obj, request.DATA)
                logger.info('Registration done. Getting access token')
                auth_data = curl_data(
                    user_obj.email,
                    serializer.data['password'], request)
                if 'error' not in auth_data:
                    logger.info('Got access token. Preparing response')
                    data = make_user_response(user_obj)
                    if data['image_url'].find('/static/') != -1:
                        image_url = data['image_url'].split('/static/')
                        if request.is_secure():
                            data['image_url'] = 'https://' + request.META['HTTP_HOST'] + '/static/' +image_url[1]
                        else:
                            data['image_url'] = 'http://' + request.META['HTTP_HOST'] + '/static/' +image_url[1]
                    healthtip = get_general_tip_for_register()
                    if healthtip['image_url'].startswith('/media') or healthtip['image_url'].startswith('/static'):
                        if request.is_secure():
                            healthtip['image_url'] = 'https://' + request.META['HTTP_HOST'] + healthtip['image_url']
                        else:
                            healthtip['image_url'] = 'http://' + request.META['HTTP_HOST'] + healthtip['image_url']
                    data['healthtip'] = healthtip
                    data['access_token'] = auth_data['access_token']
                    data['refresh_token'] = auth_data['refresh_token']
                    response_data = get_response_json(
                        uri=request._request.path,
                        lang=request.DATA['lang'],
                        region=request.DATA['region'],
                        created=True,
                        responsecode=201,
                        start=0,
                        count=0,
                        total=1,
                        data=data)
                    send_email_on_signup(request, user_obj)
                    logger.info('Returning the response.')
                    headers = {'access_token': data['access_token'], 'refresh_token': data['refresh_token']}
                    return Response(
                        response_data,
                        status=status.HTTP_201_CREATED, headers=headers)
                user_obj.delete()
            logger.warning('Got invalid credentials. Returning error response')
            detail = get_error_message(serializer.errors)
            response_data = get_error_json(uri=request._request.path,
                                           lang=request.DATA['lang'],
                                           region=request.DATA['region'],
                                           description='Invalid credentials',
                                           detail=detail,
                                           responsecode=400)
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        except:
            if user_obj:
                user_obj.delete()
            logger.error('Got exception. Returning Internal server error')
            response_data = get_error_json(uri=request._request.path,
                                           lang=request.DATA['lang'],
                                           region=request.DATA['region'],
                                           description='Internal server error',
                                           detail='Internal server error',
                                           responsecode=500)
            return Response(
                response_data,
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogin(APIView):
    """
    User login view
    """
    def post(self, request):
        '''Defines post method in UserLogin view'''
        logger.info('Entered Login view')
        email = request.DATA.get('email')
        password = request.DATA.get('password')
        auth_data = curl_data(email, password, request)
        logger.info('authentication with email: '+ email + 'and pwd: '+ password)
        if 'error' not in auth_data:
            logger.info('authentication was successful.')
            user = AppUser.objects.get(email=email)
            logger.info('Got access token. Preparing response')
            data = make_user_response(user)
            if data['image_url'].find('/static/') != -1:
                image_url = data['image_url'].split('/static/')
                if request.is_secure():
                    data['image_url'] = 'https://' + request.META['HTTP_HOST'] + '/static/' +image_url[1]
                else:
                    data['image_url'] = 'http://' + request.META['HTTP_HOST'] + '/static/' +image_url[1]

            new_data = make_login_response(user, request.DATA['timeZone'], request.DATA['logTime'], 'login')
            healthtip = new_data['healthtip']
            if healthtip['image_url'].startswith('/media') or healthtip['image_url'].startswith('/static'):
                if request.is_secure():
                    healthtip['image_url'] = 'https://' + request.META['HTTP_HOST'] + healthtip['image_url']
                else:
                    healthtip['image_url'] = 'http://' + request.META['HTTP_HOST'] + healthtip['image_url']
            new_data['healthtip'] = healthtip
            data.update(new_data)
            data['access_token'] = auth_data['access_token']
            data['refresh_token'] = auth_data['refresh_token']

            response_data = get_response_json(
                uri=request._request.path,
                lang=request.DATA['lang'],
                region=request.DATA['region'],
                created=False,
                responsecode=200,
                start=0,
                count=0,
                total=1,
                data=data)
            logger.info('Sending the response')
            headers = {'access_token': data['access_token'], 'refresh_token': data['refresh_token']}
            return Response(data=response_data, status=status.HTTP_200_OK, headers=headers)
        logger.info('authentication unsuccessful. Preparing response')
        response_data = get_error_json(uri=request._request.path,
                                       lang=request.DATA['lang'],
                                       region=request.DATA['region'],
                                       description='Invalid credentials',
                                       detail='Please check creds',
                                       responsecode=400)
        logger.info('Sending resposne')
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)


class SaltMixin(object):
    """Make a salt object"""
    salt = 'password_recovery'
    url_salt = 'password_recovery_url'


class RecoverPassword(SaltMixin, APIView):
    """
    recover password of a user
    """

    def get(self, request):
        """
        For send email with password reset link to user
        """
        email = request.query_params.get("email")
        try:
            user_data = AppUser.objects.get(email=email)
            if user_data:
                send_email_on_recover_password(request, user_data, self.salt)
                response_data = get_response_json(
                    uri=request._request.path,
                    lang=request.query_params.get("lang"),
                    region=request.query_params.get("region"),
                    created=False,
                    updated=True,
                    responsecode=200,
                    start=0,
                    count=0,
                    total=1,
                    message="OK")
                return Response(data=response_data, status=status.HTTP_200_OK)

            response_data = get_error_json(
                uri=request._request.path,
                lang=request.query_params.get("lang"),
                region=request.query_params.get("region"),
                description='Bad request',
                detail="Bad request",
                responsecode=400,
            )
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        except:
            response_data = get_error_json(
                uri=request._request.path,
                lang=request.query_params.get("lang"),
                region=request.query_params.get("region"),
                description='Internal server error',
                detail='Internal server error',
                responsecode=500,
            )
            return Response(
                response_data,
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RecoverPasswordMailView(SaltMixin, APIView):
    """
    recover password of a user
    """
    form = PasswordResetForm()
    token_expires = 3600 * 48

    def get(self, request, token):
        """
        For show the form to set new password if the token is valid
        """
        try:
            primary_key = signing.loads(token, max_age=self.token_expires, salt=self.salt)
            user = get_user_data(primary_key)
            if user:
                return render_to_response(
                                          'registration/email.html',
                                          {
                                          'in_browser': True,
                                           'site': RequestSite(request),
                                           'user': user,
                                           'token': signing.dumps(user.pk, salt=self.salt),
                                           'secure': request.is_secure(),
                                          })
        except signing.BadSignature:
            return render_to_response(
                'registration/show_message.html',
                {
                    'title': "invalid token",
                    'message': "sorry invalid token try again to recover password"})


class ResetPassword(SaltMixin, APIView):

    """
    recover password of a user
    """
    form = PasswordResetForm()
    token_expires = 3600 * 48

    def get(self, request, token):
        """
        For show the form to set new password if the token is valid
        """
        try:
            primary_key = signing.loads(token, max_age=self.token_expires, salt=self.salt)
        except signing.BadSignature:
            return render_to_response(
                'registration/show_message.html',
                {
                    'title': "invalid token",
                    'message': "sorry invalid token try again to recover password"})
        user = get_user_data(primary_key)
        return render_to_response(
            'registration/recovery_form.html',
            {'user': user, 'form': self.form})

    def post(self, request, token):
        """
        For set new password for the user
        """
        form = PasswordResetForm(request.DATA)
        if form.is_valid():
            user_data = get_user_data(
                signing.loads(
                    token,
                    max_age=self.token_expires,
                    salt=self.salt))
            if user_data:
                user_data.set_password(request.DATA['password1'])
                user_data.save()
                return render_to_response(
                    'registration/show_message.html',
                    {
                        'title': "Change successfully",
                        'message': "your password has Change successfully"})
            return render_to_response(
                'registration/show_message.html',
                {
                    'title': "Sorry something wrong",
                    'message': "sorry try again to set new password"})
        return render_to_response(
            'registration/show_message.html',
            {
                'title': "Sorry something wrong",
                'message': "sorry try again to set new password"})


class Logout(APIView):
    """logout user from request"""
    def get(self, request):
        """Defines get method in Logout view"""
        date_now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
        if request.auth is None or request.auth.expires < date_now:
            logger.warning('Invalid access token. Returning unAuthorized response.')
            response_data = get_error_json(
                uri=request._request.path,
                lang=request.DATA['lang'],
                region=request.DATA['region'],
                description='unAuthorized',
                detail='unAuthorized',
                responsecode=401,
            )
            return Response(response_data, status=status.HTTP_401_UNAUTHORIZED)
        logout(request)
        return Response("logout successfully")


class RefreshToken(APIView):
    """Get new access token by using refresh token"""
    def post(self, request):
        """Defines post method in RefreshToken view"""
        refreshed_data = refresh_token(request, request.DATA['token'])
        if refreshed_data:
            data = {}
            auth_data = string_to_dict(refreshed_data.replace("\"", ""))
            data['access_token'] = auth_data['access_token']
            data['refresh_token'] = auth_data[' refresh_token']
            response_data = get_response_json(
                uri=request._request.path,
                lang=request.DATA['lang'],
                region=request.DATA['region'],
                created=False,
                responsecode=200,
                start=0,
                count=0,
                total=1,
                data=data)
            return Response(data=response_data, status=status.HTTP_200_OK)
        response_data = get_error_json(
            uri=request._request.path,
            lang=request.query_params.get("lang"),
            region=request.query_params.get("region"),
            description='Bad request',
            detail="Bad request",
            responsecode=400,
        )
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
