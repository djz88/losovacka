from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),     # UI
    path("draw/", views.draw, name="draw"),  # JSON API (původní)
]

