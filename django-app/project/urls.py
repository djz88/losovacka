# project/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("los.urls")),  # UI na '/', JSON API na '/draw/'
]

