from django.urls import path

from . import views


urlpatterns = [

    path(
        "api/verify-abha-otp/",
        views.verify_abha_otp,
        name="verify_abha_otp"
    ),

    path(
        "digilocker/login/",
        views.digilocker_login,
        name="digilocker_login"
    ),

    path(
        "digilocker/callback/",
        views.digilocker_callback,
        name="digilocker_callback"
    ),

    path(
        "abha/details/",
        views.abha_details,
        name="abha_details"
    ),

]