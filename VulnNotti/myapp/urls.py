from django.conf.urls import url, include
from myapp.views import *


urlpatterns = [
    url(r'^$', MypageView.as_view(), name='mypage'),
    url(r'^table', TableView.as_view(), name='table'),

]
