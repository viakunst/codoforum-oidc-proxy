# Codoforum OIDC Proxy
This project is intended to proxy the Codoforum SSO requests to an OpenID
Connect provider. It uses the PHP Session variable to store the OIDC tokens. It
extracts the sub, name, email and picture claims, and presents them to the
configured Codoforum installation as JSON. The configured values should be:

## Codoforum config (forum.foo.bar):
- SSO Get User Path: https://proxy.foo.bar/user
- SSO Login User Path: https://proxy.foo.bar/login
- SSO Logout User Path: https://proxy.foo.bar/logout
- SSO Register User Path: https://id.provider.com

## OIDC provider config (id.provider.com):
- Scopes: openid, profile, email
- Grants: authorization_code, refresh_token
- Redirect URLs: https://proxy.foo.bar/user, https://forum.foo.bar

## Proxy config (proxy.foo.bar):
- oidc_provider: https://id.provider.com
- forum_redirect: https://forum.foo.bar