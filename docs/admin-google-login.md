# Google sign-in for Sunnymead admin

The admin page supports Google's official Sign in with Google button alongside the existing password login. The API validates Google's signature, issuer, client ID, token expiry, verified email and a short-lived browser nonce before issuing an HttpOnly session cookie.

## Activate Google sign-in

1. Open https://console.cloud.google.com/ and select or create a project.
2. In Google Auth Platform, configure Branding, Audience and Data Access for Sign in with Google. If the app is in testing, add sunnymeadgroup@gmail.com as a test user.
3. Create an OAuth client with application type **Web application**.
4. Add **https://sunnymeadgroup.co.uk** to Authorized JavaScript origins. Add any other exact origin you use for admin, such as the www address or your Cloudflare Pages preview origin. Origins have no /admin path.
5. Copy the client ID ending in .apps.googleusercontent.com.
6. In the Cloudflare Pages project, under Settings > Variables and Secrets, add:
   - GOOGLE_CLIENT_ID = the client ID from Google.
   - ADMIN_GOOGLE_EMAILS = sunnymeadgroup@gmail.com
7. Keep the existing ADMIN_PASSWORD secret and DB KV binding. ADMIN_PASSWORD continues to sign sessions and provides the password login.
8. Redeploy the Pages project with these settings and this change, then visit /admin/ and choose Sign in with Google.

No Google client secret or redirect URI is needed for this popup and JavaScript callback flow. The client ID is public; do not commit ADMIN_PASSWORD or other secrets.

## Access

Only the comma-separated emails in ADMIN_GOOGLE_EMAILS can sign in through Google. Email matching ignores case. Removing an address blocks its existing Google sessions on the next API request. Sessions last 30 days unless the user logs out or the signing secret changes.

If Google settings are absent, the admin page continues to offer the existing password login. Google login cannot be used until GOOGLE_CLIENT_ID and ADMIN_GOOGLE_EMAILS are configured.

## Deployment checks

Google login has not been exercised against a real Google OAuth client yet. After deployment, confirm that sunnymeadgroup@gmail.com can sign in, another Google account is denied, logout closes access, and password login still works.

References:
- https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid
- https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
