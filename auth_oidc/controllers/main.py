# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import base64
import hashlib
import json
import logging
import secrets
from ast import literal_eval

from werkzeug.urls import url_decode, url_encode

from odoo.addons.auth_oauth.controllers.main import (
    OAuthController,
    OAuthLogin,
    fragment_to_query_string,
)
from odoo.exceptions import AccessDenied
from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)


class OpenIDLogin(OAuthLogin):
    def _auth_oidc_hide_email_login(self):
        """Return True when the "Hide Email Login" setting is enabled."""
        return bool(
            request.env["ir.config_parameter"]
            .sudo()
            .get_param("auth_oidc.hide_email_login")
        )

    def web_login(self, *args, **kw):
        response = super(OpenIDLogin, self).web_login(*args, **kw)
        if response.is_qweb:
            response.qcontext["hide_email_login"] = self._auth_oidc_hide_email_login()
        return response

    def get_auth_signup_qcontext(self):
        result = super(OpenIDLogin, self).get_auth_signup_qcontext()
        # The auth_oauth.providers template (shared with the signup and
        # reset-password pages) references ``hide_email_login``. On those pages
        # the form is always visible, so the variable must be defined as False
        # to avoid a QWeb undefined-variable error and to keep the "- or -"
        # separator visible.
        result["hide_email_login"] = False
        return result

    def list_providers(self):
        providers = super(OpenIDLogin, self).list_providers()
        for provider in providers:
            flow = provider.get("flow")
            if flow in ("id_token", "id_token_code"):
                params = url_decode(provider["auth_link"].split("?")[-1])
                # nonce
                params["nonce"] = secrets.token_urlsafe()
                # response_type
                if flow == "id_token":
                    # https://openid.net/specs/openid-connect-core-1_0.html
                    # #ImplicitAuthRequest
                    params["response_type"] = "id_token token"
                elif flow == "id_token_code":
                    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
                    params["response_type"] = "code"
                # PKCE (https://tools.ietf.org/html/rfc7636)
                code_verifier = provider["code_verifier"]
                code_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode("ascii")).digest()
                ).rstrip(b"=")
                params["code_challenge"] = code_challenge
                params["code_challenge_method"] = "S256"
                # scope
                if provider.get("scope"):
                    if "openid" not in provider["scope"].split():
                        _logger.error("openid connect scope must contain 'openid'")
                    params["scope"] = provider["scope"]

                # append provider specific auth link params
                if provider["auth_link_params"]:
                    params_upd = literal_eval(provider["auth_link_params"])
                    params.update(params_upd)

                # auth link that the user will click
                provider["auth_link"] = "{}?{}".format(
                    provider["auth_endpoint"], url_encode(params)
                )
        return providers


class OAuthController(OAuthController):
    """Extend the base OAuth controller with a self-service link flow.

    A logged-in user can link an additional provider from their profile. The
    flow reuses the provider's authorization endpoint and the base
    ``/auth_oauth/signin`` callback (so no new redirect URI must be registered
    on the provider side); the ``state`` carries a ``link`` flag and the uid of
    the user who started the flow, which is verified on the callback to prevent
    cross-user linking.
    """

    @http.route("/auth_oidc/link/<int:provider_id>", type="http", auth="user")
    def link_start(self, provider_id, **kw):
        provider = request.env["auth.oauth.provider"].sudo().browse(provider_id)
        if not provider.exists() or not provider.enabled:
            raise AccessDenied()
        # Default to the "My Profile" form (Account Security tab) so the user
        # lands back on the page where they started the link flow.
        redirect = request.params.get("redirect") or self._auth_oidc_profile_url(
            request.session.uid
        )
        state = {
            "d": request.session.db,
            "p": provider.id,
            "r": redirect,
            "u": request.session.uid,
            "link": True,
        }
        params = dict(
            response_type="token",
            client_id=provider.client_id,
            redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
            scope=provider.scope,
            state=json.dumps(state),
        )
        # Reuse the OIDC parameter logic (nonce, PKCE, response_type, scope,
        # provider-specific params) so every supported flow can be linked.
        providers = OpenIDLogin().list_providers()
        for p in providers:
            if p["id"] == provider.id:
                # ``auth_link`` carries the base state (no ``link``/``u``).
                # Rebuild it with the link state so the ``signin`` callback can
                # tell a self-service link apart from a regular login.
                base, _, query = p["auth_link"].partition("?")
                qparams = dict(url_decode(query))
                qparams["state"] = json.dumps(state)
                return self._auth_oidc_redirect(
                    "%s?%s" % (base, url_encode(qparams))
                )
        return self._auth_oidc_redirect(
            "%s?%s" % (provider.auth_endpoint, url_encode(params))
        )

    @staticmethod
    def _auth_oidc_profile_url(uid):
        """Deep link to the user's own profile form (Account Security tab).

        ``/web#id=<uid>&action=<action_id>&model=res.users`` opens the record
        directly, unlike ``/web#action=...`` which opens the action in create
        mode.
        """
        action_id = request.env.ref("base.action_res_users_my").id
        return "/web#id=%s&action=%s&model=res.users" % (uid, action_id)

    @staticmethod
    def _auth_oidc_redirect(location):
        """303 redirect to an external (absolute) authorization endpoint.

        ``local=False`` is essential: the default ``local=True`` strips the
        scheme and netloc, turning ``http://host:8080/...`` into a relative
        ``/...`` path that the browser resolves against Odoo's own origin.
        ``no-store`` also prevents the browser from caching the redirect, so
        editing the provider's endpoint takes effect immediately.
        """
        response = request.redirect(location, 303, local=False)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @http.route("/auth_oauth/signin", type="http", auth="none")
    @fragment_to_query_string
    def signin(self, **kw):
        state = json.loads(kw.get("state") or "{}")
        # For ``auth="none"`` routes, ``ir_http._auth_method_none`` resets
        # ``request.env`` to ``uid=None``, so ``request.env.uid`` and
        # ``request.env.user`` are always empty here. The logged-in user must
        # be read from ``request.session.uid`` instead.
        session_uid = request.session.uid
        if state.get("link") and session_uid and state.get("u") == session_uid:
            provider = request.env["auth.oauth.provider"].sudo().browse(state["p"])
            user = request.env["res.users"].sudo().browse(session_uid)
            try:
                validation, access_token = request.env["res.users"].sudo()._auth_oidc_validate_token(
                    provider.id, kw
                )
                user._auth_oidc_link_account(
                    provider.id, validation["user_id"], access_token
                )
                request.env.cr.commit()
            except AccessDenied:
                return request.redirect(
                    self._auth_oidc_profile_url(session_uid) + "&oauth_link_error=1",
                    303,
                )
            redirect = state.get("r") or self._auth_oidc_profile_url(session_uid)
            return request.redirect(redirect, 303)
        return super(OAuthController, self).signin(**kw)
