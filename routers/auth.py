from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional, Literal

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

# =============================================================================
# Configuration
# =============================================================================

AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")  # optional

if not COGNITO_USER_POOL_ID or not COGNITO_CLIENT_ID:
    raise RuntimeError("Missing Cognito configuration: COGNITO_USER_POOL_ID / COGNITO_CLIENT_ID")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)


def _secret_hash(username: str) -> Optional[str]:
    """
    Compute SECRET_HASH iff the app client has a secret.
    """
    if not COGNITO_CLIENT_SECRET:
        return None
    message = (username + COGNITO_CLIENT_ID).encode("utf-8")
    key = COGNITO_CLIENT_SECRET.encode("utf-8")
    dig = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


# =============================================================================
# Request/Response Schemas
# =============================================================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class ConfirmSignupRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=1)


class ResendConfirmationRequest(BaseModel):
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RespondMFARequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=1)
    session: str = Field(..., min_length=1)
    mfa_type: Literal["SMS_MFA", "SOFTWARE_TOKEN_MFA"]


class CompleteNewPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str
    session: str


class RefreshTokenRequest(BaseModel):
    # Some Cognito setups require USERNAME to compute SECRET_HASH on refresh.
    email: Optional[EmailStr] = None
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


class LogoutRequest(BaseModel):
    access_token: str  # from AuthenticationResult.AccessToken


class RevokeRequest(BaseModel):
    # Works only if your app client has a client secret.
    refresh_token: str


# =============================================================================
# Error Mapping (industry-style phrasing)
# =============================================================================

def _friendly_error(e: Exception) -> str:
    """
    Map Cognito exceptions to end-user friendly messages without leaking details.
    """
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "UnknownError")

        # Sign up / confirmation / resend
        if code == "UsernameExistsException":
            return "An account with this email already exists. Try signing in or use a different email."
        if code == "InvalidPasswordException":
            return ("Your password doesn’t meet the requirements. "
                    "Use at least 8 characters, with uppercase, lowercase, a number, and a symbol.")
        if code == "InvalidParameterException":
            return "Some details look invalid. Please review and try again."
        if code == "CodeMismatchException":
            return "That verification code isn’t correct. Please re-enter it."
        if code == "ExpiredCodeException":
            return "That verification code has expired. Request a new code and try again."
        if code in ("TooManyRequestsException", "LimitExceededException"):
            return "Too many attempts. Please wait a moment and try again."
        if code == "UserNotFoundException":
            return "We couldn’t find an account with that email."
        if code == "UserNotConfirmedException":
            return "Your account isn’t confirmed yet. Please check your email for the verification link."

        # Sign in / token flows
        if code == "NotAuthorizedException":
            # Cognito returns this for bad credentials, expired refresh tokens, client secret mismatch, etc.
            msg = e.response.get("Error", {}).get("Message", "")
            if "SECRET_HASH" in msg:
                # Developer-side misconfig, but show safe message to end users.
                return "Sign-in is unavailable at the moment. Please try again shortly."
            if "Refresh Token has expired" in msg:
                return "Your session has expired. Please sign in again."
            return "Incorrect email or password. Please try again."
        if code == "PasswordResetRequiredException":
            return "You need to reset your password before signing in."
        if code == "SoftwareTokenMFANotFoundException":
            return "An authenticator app isn’t set up for this account."
        if code == "MFAMethodNotFoundException":
            return "That MFA method isn’t enabled for this account."

        # Misc/infra
        if code == "ResourceNotFoundException":
            return "The authentication service is currently unavailable. Please try again later."
        if code == "InternalErrorException":
            return "Something went wrong on our side. Please try again."

        # Fallback
        return "Something went wrong. Please try again."

    return "An unexpected error occurred. Please try again."


# =============================================================================
# Router
# =============================================================================

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def register_user(data: RegisterRequest):
    """
    Create a user account (email/password). If email confirmation is enabled,
    user must confirm before first sign-in.
    """
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": data.email,
            "Password": data.password,
            "UserAttributes": [{"Name": "email", "Value": data.email}],
        }
        if data.name:
            params["UserAttributes"].append({"Name": "name", "Value": data.name})
        sh = _secret_hash(data.email)
        if sh:
            params["SecretHash"] = sh

        cognito.sign_up(**params)
        return {
            "status": "pending_confirmation",
            "message": "Account created. Please check your email for the verification code.",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/confirm-signup")
def confirm_signup(data: ConfirmSignupRequest):
    """
    Confirm a newly created account with the emailed code.
    """
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": data.email,
            "ConfirmationCode": data.code,
        }
        sh = _secret_hash(data.email)
        if sh:
            params["SecretHash"] = sh

        cognito.confirm_sign_up(**params)
        return {"status": "confirmed", "message": "Email confirmed. You can now sign in."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/resend-confirmation")
def resend_confirmation(data: ResendConfirmationRequest):
    """
    Resend the confirmation code.
    """
    try:
        params = {"ClientId": COGNITO_CLIENT_ID, "Username": data.email}
        sh = _secret_hash(data.email)
        if sh:
            params["SecretHash"] = sh

        cognito.resend_confirmation_code(**params)
        return {
            "status": "code_sent",
            "message": "We’ve sent a new verification code to your email.",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/login")
def login(data: LoginRequest):
    """
    Sign in with email/password.
    Handles MFA (SMS/TOTP) and NEW_PASSWORD_REQUIRED challenges.
    """
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"USERNAME": data.email, "PASSWORD": data.password},
        }
        sh = _secret_hash(data.email)
        if sh:
            params["AuthParameters"]["SECRET_HASH"] = sh

        resp = cognito.initiate_auth(**params)

        # Challenges
        if "ChallengeName" in resp:
            challenge = resp["ChallengeName"]
            session = resp.get("Session", "")
            if challenge in ("SMS_MFA", "SOFTWARE_TOKEN_MFA"):
                return {
                    "status": "mfa_required",
                    "mfa_type": challenge,
                    "message": "Enter the verification code to continue.",
                    "session": session,
                }
            if challenge == "NEW_PASSWORD_REQUIRED":
                return {
                    "status": "new_password_required",
                    "message": "You need to set a new password to continue.",
                    "session": session,
                }
            # Unhandled challenge types
            return {
                "status": "challenge",
                "challenge": challenge,
                "message": "Additional verification is required.",
                "session": session,
            }

        # Success
        ar = resp["AuthenticationResult"]
        return {
            "status": "authenticated",
            "access_token": ar["AccessToken"],
            "id_token": ar.get("IdToken"),
            "refresh_token": ar.get("RefreshToken"),
            "expires_in": ar.get("ExpiresIn"),
            "token_type": ar.get("TokenType", "Bearer"),
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=_friendly_error(e))


@router.post("/respond-mfa")
def respond_mfa(data: RespondMFARequest):
    """
    Complete MFA (SMS or TOTP) after /login returns mfa_required.
    """
    try:
        responses = {"USERNAME": data.email}
        key = "SMS_MFA_CODE" if data.mfa_type == "SMS_MFA" else "SOFTWARE_TOKEN_MFA_CODE"
        responses[key] = data.code

        sh = _secret_hash(data.email)
        if sh:
            responses["SECRET_HASH"] = sh

        resp = cognito.respond_to_auth_challenge(
            ClientId=COGNITO_CLIENT_ID,
            ChallengeName=data.mfa_type,
            Session=data.session,
            ChallengeResponses=responses,
        )
        # Success
        ar = resp["AuthenticationResult"]
        return {
            "status": "authenticated",
            "access_token": ar["AccessToken"],
            "id_token": ar.get("IdToken"),
            "refresh_token": ar.get("RefreshToken"),
            "expires_in": ar.get("ExpiresIn"),
            "token_type": ar.get("TokenType", "Bearer"),
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=_friendly_error(e))


@router.post("/complete-new-password")
def complete_new_password(data: CompleteNewPasswordRequest):
    """
    Complete NEW_PASSWORD_REQUIRED challenge after /login.
    """
    try:
        responses = {
            "USERNAME": data.email,
            "NEW_PASSWORD": data.new_password,
        }
        sh = _secret_hash(data.email)
        if sh:
            responses["SECRET_HASH"] = sh

        resp = cognito.respond_to_auth_challenge(
            ClientId=COGNITO_CLIENT_ID,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=data.session,
            ChallengeResponses=responses,
        )
        ar = resp["AuthenticationResult"]
        return {
            "status": "authenticated",
            "access_token": ar["AccessToken"],
            "id_token": ar.get("IdToken"),
            "refresh_token": ar.get("RefreshToken"),
            "expires_in": ar.get("ExpiresIn"),
            "token_type": ar.get("TokenType", "Bearer"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/refresh")
def refresh_tokens(data: RefreshTokenRequest):
    """
    Exchange a refresh token for new access/id tokens.
    If your app client has a secret, include email so we can compute SECRET_HASH.
    """
    try:
        auth_params = {"REFRESH_TOKEN": data.refresh_token}
        if COGNITO_CLIENT_SECRET:
            # Some setups require USERNAME for SECRET_HASH on refresh.
            if not data.email:
                raise HTTPException(
                    status_code=400,
                    detail="Email is required to refresh tokens for this application."
                )
            sh = _secret_hash(data.email)
            auth_params["SECRET_HASH"] = sh

        resp = cognito.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=auth_params,
        )
        ar = resp["AuthenticationResult"]
        return {
            "status": "refreshed",
            "access_token": ar["AccessToken"],
            "id_token": ar.get("IdToken"),
            "expires_in": ar.get("ExpiresIn"),
            "token_type": ar.get("TokenType", "Bearer"),
            # AWS usually does not return a new refresh token here
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=_friendly_error(e))


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    """
    Start password reset (sends code to the user’s email).
    """
    try:
        params = {"ClientId": COGNITO_CLIENT_ID, "Username": data.email}
        sh = _secret_hash(data.email)
        if sh:
            params["SecretHash"] = sh

        cognito.forgot_password(**params)
        return {
            "status": "code_sent",
            "message": "We’ve emailed you a reset code. Enter it to set a new password.",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    """
    Complete password reset by providing the emailed code and a new password.
    """
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": data.email,
            "ConfirmationCode": data.code,
            "Password": data.new_password,
        }
        sh = _secret_hash(data.email)
        if sh:
            params["SecretHash"] = sh

        cognito.confirm_forgot_password(**params)
        return {"status": "password_reset", "message": "Your password has been updated. You can now sign in."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/logout")
def logout(data: LogoutRequest):
    """
    Global sign-out using an Access Token (invalidates all devices).
    """
    try:
        cognito.global_sign_out(AccessToken=data.access_token)
        return {"status": "signed_out", "message": "You’ve been signed out on all devices."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/revoke")  # optional
def revoke_refresh_token(data: RevokeRequest):
    """
    Revoke a refresh token. Requires the app client to have a client secret.
    """
    try:
        if not COGNITO_CLIENT_SECRET:
            # Don’t expose internals; keep this generic.
            raise HTTPException(status_code=400, detail="Refresh token revocation isn’t available for this application.")

        cognito.revoke_token(
            Token=data.refresh_token,
            ClientId=COGNITO_CLIENT_ID,
            ClientSecret=COGNITO_CLIENT_SECRET,
        )
        return {"status": "revoked", "message": "The session has been revoked."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))