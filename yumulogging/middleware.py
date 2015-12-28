"""Defines middleware for beingwell logging app"""

# application imports
from yumu.settings import LOGGING

# python imports
import time
import pytz
import logging
import datetime

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('django')

def valiate_access_token(user_id, data):
    """
    Validating the AccessToken
    """
    logger.info('Validating user by considering the user_d from url and user from request.auth')
    date_now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    if data and data.expires > date_now:
        if data.user.id == int(user_id):
            return data.user
        else:
            return False
    else:
        return {'error': True}
