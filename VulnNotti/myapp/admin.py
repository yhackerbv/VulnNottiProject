from django.contrib import admin
from myapp.models import *
# Register your models here.

class UploadFileAdmin(admin.ModelAdmin):
    list_display = ('title', 'file')

admin.site.register(UploadFileModel, UploadFileAdmin)
