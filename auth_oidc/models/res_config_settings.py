# Copyright 2026
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    auth_oidc_hide_email_login = fields.Boolean(
        string="Hide Email Login",
        config_parameter="auth_oidc.hide_email_login",
        help="Hide the email/password login form on the login screen. "
        "Users can only sign in through the OAuth provider buttons.",
    )
