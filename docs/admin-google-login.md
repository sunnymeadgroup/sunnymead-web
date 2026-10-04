# Google-only access to Sunnymead books

The /admin/ bookkeeping workspace uses Google sign-in exclusively. The password field and password login endpoint have been removed. Old password session cookies no longer grant access.

## Cloudflare settings

Keep:
- GOOGLE_CLIENT_ID: the OAuth Web client ID ending in .apps.googleusercontent.com.
- ADMIN_GOOGLE_EMAILS: sunnymeadgroup@gmail.com
- DB: the existing KV binding.

Session signing requires a secret. The existing ADMIN_PASSWORD value is used only to sign and verify sessions; it cannot be used to log in. Do not delete it unless you also set ADMIN_SESSION_SECRET to a strong random secret. ADMIN_SESSION_SECRET takes precedence if set. Changing the signing secret logs out existing sessions.

## Google settings

In Google Auth Platform > Clients > Sunnymead Admin, register each exact website origin used for admin under Authorized JavaScript origins:
- https://sunnymeadgroup.co.uk
- https://www.sunnymeadgroup.co.uk if used

Do not add /admin/ to these origins. If using a Pages preview URL, register that exact origin as well. No client secret or redirect URI is needed for the popup callback flow.

Only emails listed in ADMIN_GOOGLE_EMAILS can access the workspace. Removing an email blocks its current Google sessions on the next API request.

Reference: https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid
