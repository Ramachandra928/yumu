'''
Registration Mdoles defined
Login Model
Logoutmodel
'''

# python imports
import os

# django local imports
from django.db import models
from multiselectfield import MultiSelectField
from django.conf import settings as app_settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


class AppUserManager(BaseUserManager):
    """
    Application User Manager, Inherits BaseUserManager
    """
    def create_superuser(self, email, name, password, birth_year):
        """
        Application User model
        """
        if not email:
            raise ValueError('User must have a valid username')

        user = self.model(
            email=email,
            name=name,
            birth_year=birth_year,
            is_admin=True)

        user.set_password(password)
        user.save(using=self._db)
        return user


class AppUser(AbstractBaseUser):
    """
    Application User model, Inherits AbstractBaseUser
    """
    name = models.CharField(verbose_name="name", max_length=50)
    first_name = models.CharField(
        verbose_name="first_name",
        null=True,
        max_length=50)
    last_name = models.CharField(
        verbose_name="last_name",
        null=True,
        max_length=50)
    email = models.EmailField(verbose_name="email", unique=True)
    birth_year = models.PositiveIntegerField(
        verbose_name="birth_year", null=True)
    height = models.OneToOneField(Height, verbose_name="height", null=True)
    weight = models.OneToOneField(Weight, verbose_name="weight", null=True)
    image_url = models.ImageField(
        upload_to='profile',
        verbose_name="image_url",
        null=True)
    gender = models.CharField(
        choices=GENDER_CHOICES,
        verbose_name="gender",
        max_length=15,
        default='Male',
        null=True)
    settings = models.OneToOneField(
        Setting,
        verbose_name="settings",
        null=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)
    objects = AppUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'birth_year']

    def has_perm(self, perm, obj=None):
        """Does the user have a specific permission?"""
        return True

    def has_module_perms(self, app_label):
        """Does the user have permissions to view the app `app_label`?"""
        return True

    def get_short_name(self):
        """
        Method for getting Name
        """
        return self.name

    @property
    def is_staff(self):
        """Is the user a member of staff?"""
        return self.is_admin

    def save(self, *args, **kwargs):
        """model save method """
        if not self.id:
            weight = Weight()
            weight.save()
            self.weight = weight
            height = Height()
            height.save()
            self.height = height
        super(AppUser, self).save(*args, **kwargs)

    class Meta:
        """model meta data"""
        verbose_name = "Application User"
        verbose_name_plural = "Application Users"

    def __unicode__(self):
        """model __unicode__ data"""
        return self.name + " <" + self.email + ">"
