from django.urls import path

from . import views

urlpatterns = [
    path("", views.encrypt_demo, name="vault_demo"),
    path("benchmark/", views.benchmark, name="vault_benchmark"),
    path("dashboard/", views.dashboard, name="vault_dashboard"),
    path("profile/", views.profile, name="vault_profile"),
    path("upload/<slug:slug>/", views.upload, name="vault_upload"),
    path("object/<uuid:object_id>/download/", views.download, name="vault_download"),
    path("object/<uuid:object_id>/delete/", views.delete, name="vault_delete"),
]
