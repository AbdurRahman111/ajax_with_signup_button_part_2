from django.contrib import admin

# Register your models here.
from user.models import UserProfile
from .models import EmailConfirmed

# Register your models here.

class EmailConfirmedAdmin(admin.ModelAdmin):
    list_display = ['user', 'first_name', 'last_name', 'activation_key', 'email_confirmed']

    def first_name(self, obj):
        return obj.user.first_name

    def last_name(self, obj):
        return obj.user.last_name

admin.site.register(EmailConfirmed, EmailConfirmedAdmin)


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user','address','age', 'phone','image_tag']

admin.site.register(UserProfile,UserProfileAdmin)