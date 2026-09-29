# Copyright 2026
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo import models


class ChangePasswordOwn(models.TransientModel):
    _inherit = "change.password.own"

    def change_password(self):
        # SSO-only users may not have a local password: skip the
        # "Security Control" password re-verification when an OAuth
        # provider is enabled.
        self.env["res.users"]._auth_oidc_bypass_identity_check()
        return super(ChangePasswordOwn, self).change_password()
