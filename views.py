import json
from django.shortcuts import (
    render,
    redirect
)

from django.http import (
    JsonResponse
)

from django.views.decorators.http import (
    require_GET
)

from .digilocker_service import (
    create_authorization_url,
    get_access_token,
    get_digilocker_user
)


# ==========================================================
# ABHA OTP VERIFICATION
# ==========================================================

def verify_abha_otp(request):

    if request.method != "POST":

        return JsonResponse(
            {
                "success": False,
                "message":
                    "POST request required."
            },
            status=405
        )

    try:

        data = json.loads(
            request.body
        )

        abha = data.get("abha")
        aadhaar = data.get("aadhaar")
        otp = data.get("otp")

        if not otp:

            return JsonResponse(
                {
                    "success": False,
                    "message":
                        "OTP is required."
                },
                status=400
            )

        # ==================================================
        # IMPORTANT
        #
        # Replace this section with your REAL
        # authorized ABHA/ABDM OTP verification.
        #
        # Do not consider a 6-digit OTP as verified.
        # ==================================================

        abha_verified = False

        # Example:
        #
        # abha_verified =
        #     your_abdm_service.verify_otp(
        #         abha,
        #         otp
        #     )

        if not abha_verified:

            return JsonResponse(
                {
                    "success": False,
                    "message":
                        "ABHA OTP could not be verified."
                },
                status=401
            )

        request.session["abha_number"] = abha

        request.session[
            "abha_verified"
        ] = True

        return JsonResponse(
            {
                "success": True
            }
        )

    except Exception as e:

        return JsonResponse(
            {
                "success": False,
                "message": str(e)
            },
            status=500
        )


# ==========================================================
# DIGILOCKER LOGIN
# ==========================================================

def digilocker_login(request):

    if not request.session.get(
        "abha_verified"
    ):

        return redirect(
            "/"
        )

    authorization_url = (
        create_authorization_url(
            request
        )
    )

    return redirect(
        authorization_url
    )


# ==========================================================
# DIGILOCKER CALLBACK
# ==========================================================

def digilocker_callback(request):

    error = request.GET.get(
        "error"
    )

    if error:

        return render(
            request,
            "medikiosk/digilocker_error.html",
            {
                "error": error
            }
        )

    code = request.GET.get(
        "code"
    )

    state = request.GET.get(
        "state"
    )

    saved_state = request.session.get(
        "digilocker_state"
    )

    verifier = request.session.get(
        "digilocker_verifier"
    )

    if not code:

        return JsonResponse(
            {
                "error":
                    "Authorization code missing."
            },
            status=400
        )

    if state != saved_state:

        return JsonResponse(
            {
                "error":
                    "Invalid OAuth state."
            },
            status=400
        )

    if not verifier:

        return JsonResponse(
            {
                "error":
                    "PKCE verifier missing."
            },
            status=400
        )

    try:

        token_data = get_access_token(
            code,
            verifier
        )

        access_token = token_data.get(
            "access_token"
        )

        if not access_token:

            return JsonResponse(
                {
                    "error":
                        "Access token not received."
                },
                status=400
            )

        # Get DigiLocker user details
        user_data = get_digilocker_user(
            access_token
        )

        # Store only required data in session
        request.session[
            "digilocker_user"
        ] = user_data

        # Do not expose access token to frontend.
        request.session[
            "digilocker_authenticated"
        ] = True

        return redirect(
            "abha_details"
        )

    except Exception as e:

        return JsonResponse(
            {
                "error":
                    "DigiLocker authentication failed.",
                "details":
                    str(e)
            },
            status=500
        )


# ==========================================================
# ABHA DETAILS PAGE
# ==========================================================

def abha_details(request):

    if not request.session.get(
        "digilocker_authenticated"
    ):

        return redirect(
            "digilocker_login"
        )

    user = request.session.get(
        "digilocker_user",
        {}
    )

    context = {

        "abha_number":
            request.session.get(
                "abha_number",
                ""
            ),

        "digilocker_id":
            user.get(
                "digilockerid",
                user.get(
                    "digilocker_id",
                    ""
                )
            ),

        "name":
            user.get(
                "name",
                ""
            ),

        "dob":
            user.get(
                "dob",
                ""
            ),

        "gender":
            user.get(
                "gender",
                ""
            ),

        "mobile":
            user.get(
                "mobile",
                ""
            ),

        "email":
            user.get(
                "email",
                ""
            ),
    }

    return render(
        request,
        "medikiosk/abha_details.html",
        context
    )