This module depends on the
[python-jose](https://pypi.org/project/python-jose/) library, not to be
confused with `jose` which is also available on PyPI.

## Upgrading

When upgrading from a version prior to 16.0.1.5.0, the existing
single-provider links stored on the user are migrated to the new
`auth.oauth.account` model automatically. The legacy single-provider
fields are kept in sync for backward compatibility.
