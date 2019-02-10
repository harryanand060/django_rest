from django.contrib import admin

from .models import User, Verification

# Register your models here.



class UserAdmin(admin.ModelAdmin):
    list_display = ( 'first_name','email')


admin.site.register(User,UserAdmin)
admin.site.register(Verification)