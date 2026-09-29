# Copyright 2026
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo import fields, models


class AuthOauthAccount(models.Model):
    """A user's linked identity on an OAuth provider.

    A user may link several providers; each (provider, oauth_uid) pair maps
    to exactly one user, preserving the invariant of the base ``auth_oauth``
    module while allowing multiple providers per user.
    """

    _name = "auth.oauth.account"
    _description = "OAuth Account"
    _order = "provider_id, id"

    user_id = fields.Many2one(
        "res.users",
        string="User",
        required=True,
        ondelete="cascade",
        index=True,
    )
    provider_id = fields.Many2one(
        "auth.oauth.provider",
        string="Provider",
        required=True,
        ondelete="cascade",
        index=True,
    )
    provider_name = fields.Char(
        related="provider_id.name",
        string="Provider Name",
        store=False,
    )
    oauth_uid = fields.Char(
        string="OAuth User ID",
        required=True,
        help="The provider's unique identifier for this user (e.g. the "
        "OpenID Connect ``sub`` claim).",
    )
    oauth_access_token = fields.Char(
        string="OAuth Access Token",
        readonly=True,
        copy=False,
        prefetch=False,
    )

    _sql_constraints = [
        (
            "uniq_provider_uid",
            "unique(provider_id, oauth_uid)",
            "An OAuth UID must be unique per provider",
        ),
        (
            "uniq_user_provider_uid",
            "unique(user_id, provider_id, oauth_uid)",
            "A user can link a given provider only once",
        ),
    ]
