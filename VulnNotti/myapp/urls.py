from django.conf.urls import url, include
from myapp.views import *

app_name = 'myapp'
urlpatterns = [
    url(r'^static/', StaticView.as_view(), name='static'),
    url(r'^dynamic/', DynamicView.as_view(), name='dynamic'),
]
