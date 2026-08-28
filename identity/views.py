import base64
import hashlib
import secrets

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect

from identity.config import get_kinde_config
from identity.kinde_client import get_kinde_oauth
from identity.models import ExternalIdentity
from identity.session import clear_authenticated_user, set_authenticated_user

SESSION_STATE = "kinde_oauth_state"
SESSION_NONCE = "kinde_oauth_nonce"
SESSION_VERIFIER = "kinde_oauth_code_verifier"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _clear_oauth_session(request):
    for k in (SESSION_STATE, SESSION_NONCE, SESSION_VERIFIER):
        request.session.pop(k, None)


def login(request):
    cfg = get_kinde_config()
    if cfg is None:
        return HttpResponse("Kinde not configured", status=503)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(52)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())

    request.session[SESSION_STATE] = state
    request.session[SESSION_NONCE] = nonce
    request.session[SESSION_VERIFIER] = verifier

    oauth = get_kinde_oauth(cfg)
    from kinde_sdk.auth.login_options import LoginOptions

    data = async_to_sync(oauth.generate_auth_url)(
        login_options={
            LoginOptions.STATE: state,
            LoginOptions.NONCE: nonce,
            LoginOptions.CODE_CHALLENGE: challenge,
            LoginOptions.CODE_CHALLENGE_METHOD: "S256",
        }
    )
    url = data["url"]
    return redirect(url)


def callback(request):
    cfg = get_kinde_config()
    if cfg is None:
        return HttpResponse("Kinde not configured", status=503)

    state = request.GET.get("state")
    code = request.GET.get("code")
    stored_state = request.session.get(SESSION_STATE)
    verifier = request.session.get(SESSION_VERIFIER)

    if not state or not stored_state or state != stored_state:
        _clear_oauth_session(request)
        return HttpResponse("Invalid state", status=400)

    if not code:
        _clear_oauth_session(request)
        return HttpResponse("Missing code", status=400)

    if not verifier:
        _clear_oauth_session(request)
        return HttpResponse("Missing verifier", status=400)

    oauth = get_kinde_oauth(cfg)
    try:
        token_data = async_to_sync(oauth.exchange_code_for_tokens)(code, verifier)
    except Exception:
        _clear_oauth_session(request)
        return HttpResponse("Token exchange failed", status=400)

    access_token = token_data.get("access_token")
    if not access_token:
        _clear_oauth_session(request)
        return HttpResponse("Invalid token response", status=400)

    try:
        from kinde_sdk.auth.token_manager import TokenManager
        from kinde_sdk.core.helpers import get_user_details as _get_user_details

        TokenManager.reset_instances()
        tm = TokenManager("__callback__", cfg.client_id, cfg.client_secret, oauth.token_url)
        tm.set_tokens(token_data)
        try:
            user_info = async_to_sync(_get_user_details)(
                userinfo_url=oauth.userinfo_url,
                token_manager=tm,
                logger=oauth._logger,
            )
        finally:
            TokenManager.reset_instances()
    except Exception:
        try:
            import jwt

            claims = jwt.decode(access_token, options={"verify_signature": False})
            user_info = claims
        except Exception:
            _clear_oauth_session(request)
            return HttpResponse("Failed to retrieve user", status=400)

    external_id = str(user_info.get("sub") or user_info.get("id") or "")
    if not external_id:
        _clear_oauth_session(request)
        return HttpResponse("Missing subject", status=400)

    email = (user_info.get("email") or "").strip().lower()

    User = get_user_model()
    with transaction.atomic():
        try:
            ident = ExternalIdentity.objects.select_related("user").get(provider="kinde", external_id=external_id)
            user = ident.user
        except ExternalIdentity.DoesNotExist:
            username = f"kinde_{external_id}"
            base = username[:150]
            username = base
            suffix = 0
            while User.objects.filter(username=username).exists():
                suffix += 1
                username = f"{base[:140]}_{suffix}"
            user = User.objects.create(username=username, email=email)
            ExternalIdentity.objects.create(provider="kinde", external_id=external_id, user=user)

    set_authenticated_user(request, user.id)
    _clear_oauth_session(request)
    return redirect("/")


def logout(request):
    clear_authenticated_user(request)
    _clear_oauth_session(request)
    cfg = get_kinde_config()
    if cfg is not None:
        try:
            oauth = get_kinde_oauth(cfg)
            url = async_to_sync(oauth.logout)(logout_options={"post_logout_redirect_uri": "/"})
            return redirect(url)
        except Exception:
            pass
    return redirect("/")
