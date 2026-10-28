from django.urls import path

from . import views

urlpatterns = [
    path("", views.encrypt_demo, name="vault_demo"),
    path("benchmark/", views.benchmark, name="vault_benchmark"),
    path("dashboard/", views.dashboard, name="vault_dashboard"),
    path("profile/", views.profile, name="vault_profile"),
    path("loan/", views.loan, name="vault_loan"),
    path("liveness/", views.liveness, name="vault_liveness"),
    path("liveness/challenge/", views.liveness_challenge, name="vault_liveness_challenge"),
    path("liveness/submit/", views.liveness_submit, name="vault_liveness_submit"),
    path("upload/<slug:slug>/", views.upload, name="vault_upload"),
    path("object/<uuid:object_id>/download/", views.download, name="vault_download"),
    path("object/<uuid:object_id>/delete/", views.delete, name="vault_delete"),
]
