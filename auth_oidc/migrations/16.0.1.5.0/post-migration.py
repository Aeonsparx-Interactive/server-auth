# Copyright 2026
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

"""Migrate the legacy single-provider fields on ``res.users`` to the new
``auth.oauth.account`` model.

For every user that has a legacy ``oauth_provider_id`` and ``oauth_uid``, an
``auth.oauth.account`` row is created (if not already present). The legacy
fields are left untouched for backward compatibility. The script is idempotent.
"""

from odoo import SUPERUSER_ID, api


def migrate(cr, registry):
    env = api.Environment(cr, SUPERUSER_ID, {})
    users = env["res.users"].sudo().search(
        [
            ("oauth_provider_id", "!=", False),
            ("oauth_uid", "!=", False),
        ]
    )
    account_model = env["auth.oauth.account"].sudo()
    for user in users:
        existing = account_model.search(
            [
                ("user_id", "=", user.id),
                ("provider_id", "=", user.oauth_provider_id.id),
                ("oauth_uid", "=", user.oauth_uid),
            ],
            limit=1,
        )
        if existing:
            continue
        account_model.create(
            {
                "user_id": user.id,
                "provider_id": user.oauth_provider_id.id,
                "oauth_uid": user.oauth_uid,
                "oauth_access_token": user.oauth_access_token,
            }
        )
