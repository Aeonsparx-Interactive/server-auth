# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

{
    "name": "Authentication OpenID Connect",
    "version": "16.0.1.5.0",
    "license": "AGPL-3",
    "author": (
        "ICTSTUDIO, André Schenkels, "
        "ACSONE SA/NV, "
        "Odoo Community Association (OCA)"
    ),
    "maintainers": ["sbidoul"],
    "website": "https://github.com/OCA/server-auth",
    "summary": "Allow users to login through OpenID Connect Provider",
    "external_dependencies": {"python": ["python-jose"]},
    "depends": ["auth_oauth"],
    "data": [
        "security/ir.model.access.csv",
        "security/ir.rule.xml",
        "views/auth_oauth_provider.xml",
        "views/auth_oidc_templates.xml",
        "views/res_config_settings_views.xml",
        "views/res_users_views.xml",
        "data/auth_oidc_mail_template.xml",
        "data/auth_oauth_data.xml",
    ],
    "assets": {
        "web.assets_backend": [
            "auth_oidc/static/src/scss/oauth_account_widget.scss",
            "auth_oidc/static/src/js/oauth_account_widget.js",
        ],
    },
    "demo": ["demo/local_keycloak.xml"],
}
