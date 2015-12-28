"""Defines forms for registration app"""

from django import forms


class PasswordResetForm(forms.Form):
    """Form for reset the password"""
    password1 = forms.CharField(
        label='New password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control logpadding',
                'placeholder': "New Password"}),
    )
    password2 = forms.CharField(
        label='New password (confirm)',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control logpadding',
                'placeholder': "New Password(confirm)"}),
    )

    def clean_password2(self):
        """method to validate password"""
        password1 = self.cleaned_data.get('password1', '')
        password2 = self.cleaned_data['password2']
        if not password1 == password2:
            raise forms.ValidationError("The two passwords didn't match.")
        return password2
