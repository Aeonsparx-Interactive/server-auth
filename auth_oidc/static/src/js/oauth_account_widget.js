/** @odoo-module **/

import { registry } from "@web/core/registry";
import { _t } from "@web/core/l10n/translation";
import { standardFieldProps } from "@web/views/fields/standard_field_props";
import { Component, xml } from "@odoo/owl";

/**
 * Self-service widget to link/unlink the current user's OAuth providers.
 *
 * Renders one row per *enabled* provider with a Link button (redirects to the
 * provider's authorization endpoint via ``/auth_oidc/link/<id>``) or an Unlink
 * button (calls ``auth_oidc_unlink_account``). The provider list and the
 * linked state are provided by the computed ``oauth_account_widget_data`` field
 * (a JSON string) so the widget does not need read access to the provider model.
 */
export class OauthAccountWidget extends Component {
    get providers() {
        return JSON.parse(this.props.value || "[]");
    }

    get isInternal() {
        return this.props.record.data.share === false;
    }

    onLink(provider) {
        window.location.href = `/auth_oidc/link/${provider.id}`;
    }

    async onUnlink(provider) {
        await this.env.services.orm.call(
            "res.users",
            "auth_oidc_unlink_account",
            [[this.props.record.resId], provider.id]
        );
        // Reload the record from the server so the computed
        // ``oauth_account_widget_data`` field is recomputed, then notify the
        // model so the form view re-renders with the updated provider list.
        await this.props.record.load();
        this.props.record.model.notify();
    }

    t(str) {
        return _t(str);
    }
}

OauthAccountWidget.template = xml`
    <div t-if="isInternal" class="o_auth_oidc_accounts">
        <div t-foreach="providers" t-as="provider" t-key="provider.id"
             class="o_auth_oidc_account">
            <span t-attf-class="o_auth_oidc_icon {{ provider.css_class || '' }}"/>
            <span class="o_auth_oidc_name" t-esc="provider.name"/>
            <span t-if="provider.linked_uid" class="o_auth_oidc_uid"
                  t-esc="provider.linked_uid"/>
            <button t-if="provider.linked_uid" type="button"
                    class="btn btn-sm btn-secondary o_auth_oidc_btn"
                    t-on-click="() => this.onUnlink(provider)">
                <t t-esc="t('Unlink')"/>
            </button>
            <button t-else="" type="button" class="btn btn-sm btn-primary o_auth_oidc_btn"
                    t-on-click="() => this.onLink(provider)">
                <t t-esc="t('Link')"/>
            </button>
        </div>
        <div t-if="!providers.length" class="text-muted o_auth_oidc_empty">
            <t t-esc="t('No enabled OAuth provider.')"/>
        </div>
    </div>
`;

OauthAccountWidget.props = {
    ...standardFieldProps,
};

registry.category("fields").add("auth_oidc_oauth_account", OauthAccountWidget);
