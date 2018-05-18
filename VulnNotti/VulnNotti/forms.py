from django.contrib.auth.forms import UserCreationForm
from django.forms import EmailField, URLField
from django import forms
from django.contrib.auth.models import User

class UserCreationForm(UserCreationForm):
    email = EmailField(label=("이메일"), required=True,
        help_text=("이메일을 등록하세요."))

    repository = URLField(label=("레포지토리"), required=True,
        help_text=("github 레포지토리를 등록하세요."))


class UserEditForm(forms.Form):
    email = EmailField(label=("이메일"), required=True,
        help_text=("이메일을 입력하세요."))

    repository = URLField(label=("레포지토리"), required=True,
        help_text=("github 레포지토리를 입력하세요."))


    class Meta:
        model = User
        fields = ("username", "email", "repository", "password1", "password2")

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        user.repository = self.cleaned_data["repository"]
        if commit:
            user.save()
        return user
