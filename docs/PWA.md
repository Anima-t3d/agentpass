# Approval app (PWA) and push notifications

## What it is

The passkey approval page doubles as an installable web app. It adds, on top of the page described in [DESIGN.md](DESIGN.md) section 3.4:

- passkey sign-in, so the page can show more than a single request;
- Web Push notifications that say what is being asked (agent and tool, plus the headline of the trusted preview, or the request signature when there is none), with **Approve** and **Deny** actions;
- a **History** tab over the audit log and a **Devices** tab for the devices that receive notifications;
- handling for a device that is temporarily off the private network.

Telegram and the other channels keep working unchanged. Whichever trusted channel answers first resolves the request.

## Requirements

- The passkey approval page is enabled (`passkey.enabled`) and a passkey is enrolled (`agentpass passkey enroll`).
- The page is served over HTTPS on a private network, for example a tailnet via `tailscale serve`. Service workers, WebAuthn and push all need a secure origin. Do not publish it on the public internet.
- Devices must be able to reach that origin to sign in and to answer. Notifications themselves arrive through the browser's own push service and do not need the private network.

## Enabling push

Add a `push` block under `passkey` in `config.yaml`:

```yaml
passkey:
  enabled: true
  rp_id: gate.example.org
  origin: https://gate.example.org
  push:
    enabled: true
    subject: mailto:admin@example.org   # VAPID contact: mailto: or https://
    # vapid_key_path: /var/lib/agentpass/push-vapid.pem   # default: next to the database
    # timeout: 10                       # seconds per push request (0 to 60)
```

`push.enabled` requires `passkey.enabled`, and `subject` is mandatory when push is enabled.

Create the VAPID key as the user the gateway runs as, so the file is owned by it:

```bash
sudo -u agentpass agentpass push init-keys --config /etc/agentpass/config.yaml
```

The command creates the key at `vapid_key_path` with mode 0600 if it does not exist, and prints `VAPID public key: <base64url>`. If the key already exists it is left untouched and the same public key is printed, so the command is safe to repeat. It never prints the private key and works while `push.enabled` is still false, so you can create the key before enabling push. Restart the gateway after enabling push.

## Installing the app

Open the page origin in the browser, sign in with your passkey, then:

- **Android Chrome**: menu, "Install app" (or "Add to Home screen"). Allow notifications when the app asks.
- **Desktop Chrome and Edge**: the install icon in the address bar, or menu, "Install AgentPass". Allow notifications when asked.
- **Desktop Firefox**: Firefox does not install web apps on desktop, but the page works in a tab and can receive notifications while the browser is running.
- **iOS and iPadOS**: push works only for an app added to the Home screen (Safari, Share, "Add to Home Screen"). Notifications show no action buttons: tapping one opens the app on the request. iOS is not a primary target.

Turning on notifications on a device registers it in the **Devices** tab.

## Sign-in

The app signs in with a passkey assertion against the enrolled passkeys. The session is a cookie (`HttpOnly; Secure; SameSite=Strict; Path=/`) that expires after 12 hours without use or 7 days after sign-in, whichever comes first; the cookie's `Max-Age` is the 7 day limit. Sessions live in the gateway's memory, so a gateway restart signs everyone out.

A session only opens read views (pending requests, History, Devices) and manages notification devices. It never approves anything by itself: every in-app Approve still needs its own WebAuthn assertion bound to that request. The admin bearer token of the audit dashboard is never used or exposed by the app.

## Notifications and actions

Each notification names the agent and tool and carries the preview headline. **Deny** is always one tap: it resolves the request directly from the notification (denying is always safe). **Approve** opens the app on that request, where you confirm with your passkey, unless the device has one-tap approve on and the request qualifies (next section).

When a request resolves, in the app, in Telegram or by timeout, a "resolved" push replaces the notification on every device. A notification tapped after that fails cleanly with "already resolved". "Allow always" and "Deny always" remembered rules are not offered from notifications, only in the app.

## One-tap approve

One-tap approve lets the notification's Approve button answer without opening the app.

- It is a per-device setting in the Devices tab and is **off by default**.
- Turning it on needs a fresh passkey assertion on that device. Turning it off never does.
- It is stored on the gateway only; nothing in the browser can flip it.
- It applies only to rules whose requirement is `any_trusted` (the default). It never applies to `require: passkey` or `require: telegram` rules: for those, tapping Approve only opens the app, and a push answer is never counted (a `require: telegram` request can only be approved in Telegram).

## Offline behaviour

If a notification action cannot reach the gateway, for example because the phone is off the tailnet, the service worker keeps the action in a queue and changes the notification to "Waiting for Tailscale…" with a hint to open Tailscale. The queue retries when the browser allows (Background Sync where available, otherwise when the service worker next wakes or the app opens). Each action is bounded by the request's expiry: once it has passed, the notification changes to "Expired before it could be sent" and the queued action is dropped.

When the app cannot reach the origin it shows a "Not connected to Tailscale" banner, keeps the last loaded History readable and disables Approve and Deny until the connection returns.

## History

The History tab shows the audit log: who asked, which tool, the decision, how and by whom it was resolved (for example the channel and device label), when, and the result. It can be filtered by agent, tool, decision, date and result, is paginated, and is read-only. It needs a signed-in session.

## Devices

The Devices tab lists the devices that receive notifications, with their label (editable), one-tap setting and last-seen time. A device can be renamed or removed. A device whose subscription the push service reports as gone (HTTP 404 or 410) is removed automatically.

## Security model

- **Payload encryption.** Push messages are encrypted for the subscribing browser with Web Push message encryption (RFC 8291, `aes128gcm`) and authenticated to the push service with VAPID (RFC 8292). The push service (for example Google or Mozilla) relays ciphertext. It sees the device's endpoint, message size and timing, not the content.
- **Minimal payload.** A push carries only a type, the approval id, a display title and body, the requirement, the one-tap flag, an action token and the expiry (a resolved push adds the decision and reason). No tool arguments, agent note or secrets. Details load from the gateway after sign-in.
- **Action tokens.** The token on a notification is bound to one approval and one device, expires with the approval and is single use. The signing key and the used-token record are in gateway memory only, so a restart invalidates every outstanding notification: tapping one afterwards is refused, and the request can still be answered in the app. A token is refused after the approval resolved.
- **Trust.** The push channel is `trusted` with proof kind `push_action` only. The coordinator never counts a push answer for `require: passkey` or `require: telegram`; the server, not the client, decides whether an Approve is allowed to resolve.
- **VAPID key.** The private key is a gateway secret (0600), never logged or returned by any endpoint.
- **Sessions** are in memory with the lifetimes above.
- **What is not protected.** With one-tap on, anyone who can use the unlocked device can approve `any_trusted` requests from its notifications. Leave it off for devices that are shared or often unlocked in public, or rely on `require: passkey` for high-risk rules. A compromised push service can drop or delay notifications (approvals then time out as usual) but cannot read or forge them.

## Limitations

- A rule that lists `approval.channels` explicitly never includes the push channel unless `push` is in that list. This fails closed: the request is sent to the listed channels only.
- Failed attempts to turn on one-tap appear in the audit log as rejected assertions with request id `one-tap:<device>`.
- Android and desktop browsers are the targets; iOS gets notifications without action buttons.
