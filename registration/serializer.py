"""Defines which serializers comprise the registration app"""

from rest_framework import serializers
from .models import AppUser


class RegisterSerializer(serializers.ModelSerializer):
    """ Used for Serializing the user object """
    class Meta:
        """ meta datas of model """
        model = AppUser
        fields = ('name', 'email', 'birth_year', 'password')


class UserSerializer(serializers.ModelSerializer):
    """ Used for Serializing the user object """
    class Meta:
        """ meta datas of model """
        model = AppUser
        fields = (
            'name',
            'email',
            'birth_year',
            'gender',
            'image_url')
