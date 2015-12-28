"""Defines which middlewares for registration app"""

# django imports
from django.core import signing
from django.template import loader
from django.template import Context
from django.utils.html import strip_tags
from yumuapi.models import CountrySettings
from django.template.loader import get_template
from django.contrib.sites.models import RequestSite
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

# application imports
from yumu import settings
from .models import AppUser
from .serializer import UserSerializer

# python imports
import time
import json
import pytz
import urllib2
import logging
import datetime
import threading
from geopy.geocoders import Nominatim
from timezone_constants import TIMEZONE_COUNTRY
from oauth2_provider.models import AccessToken

logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger('django')


def get_country_on_lat_long(latitude, longitude):
    url='http://maps.googleapis.com/maps/api/geocode/json?latlng='+ latitude + ',' + longitude + '&sensor=true'
    req = urllib2.Request(url)
    location_lat_long = urllib2.urlopen(req)
    result = location_lat_long.read()
    return json.loads(result)['results'][-1]['formatted_address']

class EmailThread(threading.Thread):
    def __init__(self, subject, body, email, html_content):
        self.body = body
        self.email = email
        self.subject = subject
        self.html_content = html_content
        threading.Thread.__init__(self)

    def run (self):
        logger.info('Preparing welcome email.')
        email = EmailMultiAlternatives(
                self.subject,
                self.body, 'Yumu <care@yumu.co>', [
                    self.email])
        email.attach_alternative(self.html_content, "text/html")
        logger.info('Sending welcome email.')
        email.send()


def send_alert_mail(data, response_data, exc):
    email_template_name = 'registration/alert.html'
    context = {
        'request': data,
        'error': exc,
        'response': response_data
    }
    html_content = loader.render_to_string(email_template_name,
                                           context)
    body = strip_tags(html_content)
    subject = "Error 500 on Server"
    email = EmailMultiAlternatives(
                subject,
                body, 'Yumu <care@yumu.co>', [
                    'ram@yumu.in'])
    email.attach_alternative(html_content, "text/html")
    email.send()
    return True

def send_email_on_signup(request, user_data):
    '''
    Method for sending welcome email after sign up
    '''
    email_template_name = 'registration/welcome.html'
    context = {
        'site': RequestSite(request),
        'user': user_data,
        'token': signing.dumps(user_data.pk, salt='Welcome Diabeat'),
        'secure': request.is_secure(),
        'host': request.META.get('HTTP_HOST')
    }
    html_content = loader.render_to_string(email_template_name,
                                           context)
    body = strip_tags(html_content)
    subject = "Welcome to Yumu"
    EmailThread(subject, body, 'ram@yumu.in', html_content).start()


def send_email_on_recover_password(request, user_data, salt):
    '''
    Method for sending password reset mail
    '''
    email_template_name = 'registration/email.html'
    context = {
               'site': RequestSite(request),
               'user': user_data,
               'token': signing.dumps(user_data.pk, salt=salt),
               'secure': request.is_secure(),
              }
    html_content = loader.render_to_string(email_template_name,
                                           context)
    body = strip_tags(html_content)
    subject = "Password Reset Request"
    email = EmailMultiAlternatives(
                subject,
                body, 'Yumu <care@yumu.co>', [
                    user_data.email])
    email.attach_alternative(html_content, "text/html")
    email.send()

def curl_data(email, password, request):
    '''method to generate access token'''
    logger.info('Getting access token')
    logger.info(request.META['HTTP_HOST'])
    data = "client_id=" + settings.OAUTH_CLIENT_ID + \
           "&client_secret=" + settings.OAUTH_SECRET_KEY + \
           "&grant_type=password&username=" + email + \
           "&password=" + password + ""
    if request.is_secure():
        url = 'https://'+ request.META['HTTP_HOST']+'/o/token/'
    else:
        url = 'http://'+ request.META['HTTP_HOST']+'/o/token/'
    req = urllib2.Request(
        url, data, {
            'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        pdf_file = urllib2.urlopen(req)
        result = pdf_file.read()
        pdf_file.close()
        access_token = AccessToken.objects.get(token=json.loads(result)['access_token'])
        access_token.expires = datetime.datetime.utcnow().replace(tzinfo=pytz.utc) + datetime.timedelta(days=200)
        access_token.scope += " offline"
        access_token.save()
        return json.loads(result)
    except Exception:
        return {'error': 'Invalid creds'}

def refresh_token(request, token):
    '''method to get new access token from refresh token'''
    data = "refresh_token=" + token + \
        "&client_id=" + settings.OAUTH_CLIENT_ID + \
        "&client_secret=" + settings.OAUTH_SECRET_KEY + \
        "&grant_type=refresh_token"
    if request.is_secure():
        url = 'https://'+ request.META['HTTP_HOST']+'/o/token/'
    else:
        url = 'http://'+ request.META['HTTP_HOST']+'/o/token/'
    req = urllib2.Request(
        url, data, {
            'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        pdf_file = urllib2.urlopen(req)
        result = pdf_file.read()
        pdf_file.close()
        return result
    except Exception:
        return None

def validate_user(email, password):
    """
    This method check the user existence
    """
    user = AppUser.objects.get(email=email)
    if user and password == user.password:
        return user
    else:
        return False

def string_to_dict(string_input):
    """
    To conver string of list to list
    """
    if string_input is None or string_input == '':
        return ''
    data = string_input[1:-1].split(',')
    result = {}
    for data_value in data:
        result[data_value.split(':')[0]] = data_value.split(':')[1]
    return result

def check_user_exists(email):
    """
    This method check the user existence
    """
    try:
        AppUser.objects.get(email=email)
    except AppUser.DoesNotExist:
        return False
    return True

def get_user_data(user_id):
    """
    This method check the user existence
    """
    try:
        user = AppUser.objects.get(id=user_id)
        return user
    except AppUser.DoesNotExist:
        return None

def update_user_profile(user_id, user_obj):
    """
    :param user_obj:
    :return:
        ('name',
        'email',
        'birth_year',
        'password',
        'image_url')
    """
    user_data = get_user_data(user_id)
    weight_obj = None
    height_obj = None
    if user_data:
        if user_obj.get('profile'):
            user_profile_obj = user_obj.get('profile')
            if user_profile_obj.get('name'):
                user_data.name = user_profile_obj.get('name')
            if user_profile_obj.get('email'):
                user_data.email = user_profile_obj.get('email')
            if user_profile_obj.get('birth_year'):
                user_data.birth_year = user_profile_obj.get('birth_year')
            if user_profile_obj.get('gender'):
                user_data.gender = user_profile_obj.get('gender')
            if user_profile_obj.get('image_url'):
                user_data.image_url = user_profile_obj.get('image_url')
        if user_obj.get('settings'):
            setting_obj = user_obj.get('settings')
            user_data_settings = Setting.objects.get(id=user_data.settings.id)
        if user_obj.get('settings'):
            user_data_settings.save()
        user_data.save()
        return user_data
    return None

def get_error_message(error_data):
    '''method to get error message'''
    detail = ''
    if 'email' in error_data:
        if str(error_data['email'][0]) == 'This field is required.':
            detail = 'Email is required'
        else:
            detail = 'Email already exists.'
    elif 'name' in error_data:
        detail = 'Name is required'
    elif 'birth_year' in error_data:
        detail = 'Birth_year is required'
    else:
        detail = 'Password is required'
    return detail

def get_date_time_from_tz(utc_time, tz):
    '''
    Getting date and time as per clients timezone in milliseconds
    Converting miliseconds to %d/%m/%Y and %H:%M format
    import pytz
    '''
    hour_min = None
    neg_tz = False
    pos_tz = False
    if tz.find('-') != -1:
        new_tz = tz.split('-')
        tz = new_tz[0]
        hour_min = new_tz[1]
        neg_tz = True
    if tz.find(' ') != -1:
        new_tz = tz.split()
        tz = new_tz[0]
        hour_min = new_tz[1]
        pos_tz = True
    if tz.find('+') != -1:
        new_tz = tz.split('+')
        tz = new_tz[0]
        hour_min = new_tz[1]
        pos_tz = True
    date_time=[]
    datetime_obj = utc_time.astimezone(pytz.timezone(tz))
    date_time.append(get_excel_date(datetime_obj))
    date_time.append(datetime_obj.strftime('%H:%M'))
    return date_time

def time_zone_changer_for_request(client_datetime, client_timezone):
    """
    this method return datetime in UTC
    parameters
    client_datetime : client datetime in miliseconds
    client_timzone : client timezone
    """
    if client_timezone.find('+') != -1:
        timezone_data = client_timezone.split('+')
        client_timezone = timezone_data[0]
        time_data = timezone_data[1]
        hour_min = time_data.split(':')
        client_datetime = client_datetime + ((int(hour_min[0]) * 3600000) + (int(hour_min[1]) * 60000))
    elif client_timezone.find(' ') != -1:
        timezone_data = client_timezone.split()
        client_timezone = timezone_data[0]
        time_data = timezone_data[1]
        hour_min = time_data.split(':')
        client_datetime = client_datetime + ((int(hour_min[0]) * 3600000) + (int(hour_min[1]) * 60000))
    elif client_timezone.find('-') != -1:
        timezone_data = client_timezone.split('-')
        client_timezone = timezone_data[0]
        time_data = timezone_data[1]
        hour_min = time_data.split(':')
        client_datetime = client_datetime - ((int(hour_min[0]) * 3600000) + (int(hour_min[1]) * 60000))

    if client_timezone in all_timezones:
        current_time = datetime.datetime.fromtimestamp(client_datetime/1000)
        server_timezone = timezone(settings.TIME_ZONE)
        fmt = '%Y-%m-%d %H:%M:%S.%f'
        server_dt = server_timezone.localize(current_time)
        local_timezone = timezone(client_timezone)
        local_dt = server_dt.astimezone(local_timezone)
        return local_dt.strftime(fmt)
    else:
        return None

def time_zone_changer_for_response(server_datetime, client_timezone):
    """
    this method return datetime in clients timezone
    parameters
    server_datetime : client datetime in datetime
    client_timzone : client timezone
    """
    if client_timezone.find('+') != -1:
        timezone_data = client_timezone.split('+')
        client_timezone = timezone_data[0]
        time_data = timezone_data[1]
        hour_min = time_data.split(':')
        server_datetime += datetime.timedelta(hours=int(hour_min[0]), minutes=int(hour_min[1]))
    elif client_timezone.find('-') != -1:
        timezone_data = client_timezone.split('-')
        client_timezone = timezone_data[0]
        time_data = timezone_data[1]
        hour_min = time_data.split(':')
        server_datetime -= datetime.timedelta(hours=int(hour_min[0]), minutes=int(hour_min[1])) 
    if client_timezone in all_timezones:
        local_timezone = timezone(client_timezone)
        local_dt = server_datetime.astimezone(local_timezone)
        local_dt_in_ms = time.mktime(local_dt.timetuple()) * 1000
        return local_dt_in_ms
    else:
        return None
