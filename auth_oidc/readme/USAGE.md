On the login page, click on the authentication provider you configured.

## Linking multiple providers

A user can be linked to several OAuth providers at the same time. In the user's
own profile (My Profile > *Account Security* tab, next to the password change
and API key generation), every *enabled* provider is listed with a single
**Link** / **Unlink** button per provider:

- **Link** redirects the user to the provider's authorization page; once the
  provider identity is validated it is linked to the current user.
- **Unlink** removes the link between the current user and that provider.

Linking a provider identity that is already bound to another user is refused.
The legacy single-provider fields on the user are kept in sync for backward
compatibility, and the access token of the most recent login is stored so the
base session re-authentication keeps working.
