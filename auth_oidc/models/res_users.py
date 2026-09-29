# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import json
import logging
import time

import requests

from odoo import _, api, fields, models
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.exceptions import AccessDenied, UserError
from odoo.http import request

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    oauth_account_ids = fields.One2many(
        "auth.oauth.account",
        "user_id",
        string="OAuth Accounts",
    )
    oauth_account_widget_data = fields.Text(
        compute="_compute_oauth_account_widget_data",
        string="OAuth Account Widget Data",
    )

    @api.depends("oauth_account_ids")
    def _compute_oauth_account_widget_data(self):
        for user in self:
            providers = user._auth_oidc_enabled_providers()
            linked = {
                account.provider_id.id: account.oauth_uid
                for account in user.oauth_account_ids
            }
            for provider in providers:
                provider["linked_uid"] = linked.get(provider["id"])
            user.oauth_account_widget_data = json.dumps(providers)

    def _auth_oidc_sso_enabled(self):
        """Return True when at least one OAuth provider is enabled."""
        return bool(
            self.env["auth.oauth.provider"].sudo().search_count(
                [("enabled", "=", True)]
            )
        )

    def _auth_oidc_bypass_identity_check(self):
        """Skip the "Security Control" password re-verification.

        SSO-only users may not have a local password, so the password
        prompt from the ``check_identity`` decorator would be unusable.
        Stamping the session makes the decorator consider the identity
        as already checked.
        """
        if request and self._auth_oidc_sso_enabled():
            request.session["identity-check-last"] = time.time()

    def api_key_wizard(self):
        self._auth_oidc_bypass_identity_check()
        return super(ResUsers, self).api_key_wizard()

    def preference_change_password(self):
        self._auth_oidc_bypass_identity_check()
        return super(ResUsers, self).preference_change_password()

    def action_reset_password(self):
        """Send the new-user invitation email without the set-password link.

        SSO users authenticate through the OAuth provider, so the "Accept
        invitation" (set password) link in the new-user email is not needed.
        When SSO is enabled and the ``create_user`` context is set, the
        ``auth_oidc.set_password_email_no_link`` template is used; every other
        case is delegated to the base implementation.
        """
        if self.env.context.get("create_user") and self._auth_oidc_sso_enabled():
            if self.env.context.get("install_mode", False):
                return
            if self.filtered(lambda user: not user.active):
                raise UserError(_("You cannot perform this action on an archived user."))
            # No time limit for the initial invitation (matches base behaviour).
            self.mapped("partner_id").signup_prepare(
                signup_type="reset", expiration=False
            )
            template = self.env.ref("auth_oidc.set_password_email_no_link")
            email_values = {
                "email_cc": False,
                "auto_delete": True,
                "message_type": "user_notification",
                "recipient_ids": [],
                "partner_ids": [],
                "scheduled_date": False,
            }
            for user in self:
                if not user.email:
                    raise UserError(
                        _("Cannot send email: user %s has no email address.", user.name)
                    )
                email_values["email_to"] = user.email
                with self.env.cr.savepoint():
                    force_send = not (self.env.context.get("import_file", False))
                    template.send_mail(
                        user.id,
                        force_send=force_send,
                        raise_exception=True,
                        email_values=email_values,
                    )
                _logger.info(
                    "Password reset email sent for user <%s> to <%s>",
                    user.login,
                    user.email,
                )
            return
        return super(ResUsers, self).action_reset_password()

    def _auth_oauth_get_tokens_implicit_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
        return params.get("access_token"), params.get("id_token")

    def _auth_oauth_get_tokens_auth_code_flow(self, oauth_provider, params):
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
        code = params.get("code")
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        auth = None
        if oauth_provider.client_secret:
            auth = (oauth_provider.client_id, oauth_provider.client_secret)
        response = requests.post(
            oauth_provider.token_endpoint,
            data=dict(
                client_id=oauth_provider.client_id,
                grant_type="authorization_code",
                code=code,
                code_verifier=oauth_provider.code_verifier,  # PKCE
                redirect_uri=request.httprequest.url_root + "auth_oauth/signin",
            ),
            auth=auth,
            timeout=10,
        )
        response.raise_for_status()
        response_json = response.json()
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        return response_json.get("access_token"), response_json.get("id_token")

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        """Sign in (or create) the user for ``provider`` and validated token.

        The user is resolved through the ``auth.oauth.account`` model so that a
        single user may be linked to several providers. The legacy
        ``res.users.oauth_provider_id``/``oauth_uid`` fields are kept in sync
        for backward compatibility, and ``oauth_access_token`` is stamped on the
        user so the base session re-authentication keeps working.
        """
        oauth_uid = validation["user_id"]
        access_token = params.get("access_token")
        account = (
            self.env["auth.oauth.account"]
            .sudo()
            .search(
                [("provider_id", "=", provider), ("oauth_uid", "=", oauth_uid)],
                limit=1,
            )
        )
        if account:
            # Known provider identity: refresh the token and sign in.
            account.write({"oauth_access_token": access_token})
            user = account.user_id
            user.sudo().write({"oauth_access_token": access_token})
            self._auth_oidc_dismiss_pending_signup(user)
            return user.login
        if self.env.context.get("no_user_creation"):
            return None
        # Unknown provider identity: link it to an existing user sharing the
        # same email, or create a new user.
        email = validation.get("email")
        user = (
            self.sudo().search([("email", "=", email)], limit=1) if email else self
        )
        if not user:
            state = json.loads(params["state"])
            token = state.get("t")
            values = self._generate_signup_values(provider, validation, params)
            try:
                login, _ = self.signup(values, token)
            except (SignupError, UserError):
                raise AccessDenied()
            user = self.sudo().search([("login", "=", login)], limit=1)
        # Link the provider to the user. (For a brand-new user the legacy
        # fields were already set by _generate_signup_values on creation.)
        self.env["auth.oauth.account"].sudo().create(
            {
                "user_id": user.id,
                "provider_id": provider,
                "oauth_uid": oauth_uid,
                "oauth_access_token": access_token,
            }
        )
        user.sudo().write({"oauth_access_token": access_token})
        self._auth_oidc_dismiss_pending_signup(user)
        return user.login

    @api.model
    def _auth_oidc_dismiss_pending_signup(self, user):
        """Dismiss the pending signup so the "registration link has been sent"
        notice disappears once the user logs in with OAuth. (login_date is set
        by the base _login, marking the user active.)"""
        user.partner_id.sudo().signup_cancel()

    @api.model
    def _auth_oidc_validate_token(self, provider, params):
        """Validate the OAuth/OIDC token for ``provider``.

        Returns ``(validation, access_token)`` where ``validation`` is a dict
        containing at least ``user_id`` (the provider's unique identifier) and,
        when available, ``email``. Shared by the login flow (``auth_oauth``) and
        the self-service link flow.
        """
        oauth_provider = self.env["auth.oauth.provider"].browse(provider)
        if oauth_provider.flow == "id_token":
            access_token, id_token = self._auth_oauth_get_tokens_implicit_flow(
                oauth_provider, params
            )
        elif oauth_provider.flow == "id_token_code":
            access_token, id_token = self._auth_oauth_get_tokens_auth_code_flow(
                oauth_provider, params
            )
        else:
            # Plain OAuth2 (access_token) flow.
            access_token = params.get("access_token")
            if not access_token:
                _logger.error("No access_token in response.")
                raise AccessDenied()
            return self._auth_oauth_validate(provider, access_token), access_token
        if not access_token:
            _logger.error("No access_token in response.")
            raise AccessDenied()
        if not id_token:
            _logger.error("No id_token in response.")
            raise AccessDenied()
        validation = oauth_provider._parse_id_token(id_token, access_token)
        # required check
        if "sub" in validation and "user_id" not in validation:
            # set user_id for auth_oauth, user_id is not an OpenID Connect standard
            # claim:
            # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
            validation["user_id"] = validation["sub"]
        elif not validation.get("user_id"):
            _logger.error("user_id claim not found in id_token (after mapping).")
            raise AccessDenied()
        return validation, access_token

    @api.model
    def auth_oauth(self, provider, params):
        validation, access_token = self._auth_oidc_validate_token(provider, params)
        # retrieve and sign in user
        params["access_token"] = access_token
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)

    def _auth_oidc_enabled_providers(self):
        """Return the enabled providers as a list of dicts for the link widget."""
        providers = (
            self.env["auth.oauth.provider"]
            .sudo()
            .search([("enabled", "=", True)], order="sequence, name")
        )
        return [
            {
                "id": p.id,
                "name": p.name,
                "body": p.body,
                "css_class": p.css_class,
            }
            for p in providers
        ]

    def _auth_oidc_link_account(self, provider_id, oauth_uid, access_token):
        """Link ``self`` (the current user) to ``provider_id`` with ``oauth_uid``.

        Raises ``UserError`` if the provider identity is already linked to
        another user (enforced by the ``uniq_provider_uid`` constraint).
        """
        self.ensure_one()
        account = (
            self.env["auth.oauth.account"]
            .sudo()
            .search(
                [
                    ("provider_id", "=", provider_id),
                    ("oauth_uid", "=", oauth_uid),
                ],
                limit=1,
            )
        )
        if account and account.user_id != self:
            raise UserError(
                _("This %s account is already linked to another user.", account.provider_id.name)
            )
        if account:
            account.sudo().write({"oauth_access_token": access_token})
            return account
        return self.env["auth.oauth.account"].sudo().create(
            {
                "user_id": self.id,
                "provider_id": provider_id,
                "oauth_uid": oauth_uid,
                "oauth_access_token": access_token,
            }
        )

    def auth_oidc_unlink_account(self, provider_id):
        """Unlink ``self`` (the current user) from ``provider_id``.

        Public (no leading underscore) so it can be called via RPC from the
        self-service widget.
        """
        self.ensure_one()
        (
            self.env["auth.oauth.account"]
            .sudo()
            .search(
                [
                    ("user_id", "=", self.id),
                    ("provider_id", "=", provider_id),
                ],
                limit=1,
            )
        ).unlink()
