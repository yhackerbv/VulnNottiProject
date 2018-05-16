from django.contrib import admin
from myapp.models import Question, Choice
# Register your models here.


admin.site.register(Question)
admin.site.register(Choice)
