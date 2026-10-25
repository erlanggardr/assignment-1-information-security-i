from django.urls import path

from . import views

urlpatterns = [
    path("", views.encrypt_demo, name="vault_demo"),
    path("benchmark/", views.benchmark, name="vault_benchmark"),
]
