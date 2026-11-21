# NodeScope push relay

This standalone Go service implements the v1 CoreScope relay contract.
It defaults to simulation. Staging and production use separate encrypted
state and send through their configured APNs environment and Firebase
project. Use synthetic tokens in simulation.

## Run locally

Use Go 1.26 or later. Set `RELAY_OPERATOR_TOKEN` to a random unpadded
base64url credential of at least 32 bytes and keep it in the service
environment. Run `go test ./...` and then `go run .`.

The default listener is `127.0.0.1:8080`. `RELAY_ADDR` overrides it.
`RELAY_STATE_PATH` defaults to `relay-state.json`. Its parent directory
must exist, be private, and be writable by the relay. Run only one relay
process against a state file. The staging store uses atomic JSON snapshots
and keeps simulated device tokens in the private state file. Real-provider
mode encrypts the entire snapshot with AES-256-GCM.

To build a container, run `docker build -t nodescope-push-relay:staging .`.
Mount a writable, persistent `/data` directory owned by UID 65532, supply
the operator credential as a secret in the container environment, and put
the HTTP listener behind an HTTPS reverse proxy. Keep the listener private.
Expose `GET /healthz` to the deployment health check. Keep
`/v1/operator/` restricted to operators at the proxy as well.

## Operator access

Call `/v1/operator/` from a private path, such as the internal container
network, the relay host, or an operator-only proxy listener. Keep the route
blocked at the public proxy. The operator credential is required on the
private path too.

For example, run this in a trusted shell attached to the deployment network
with `curl`, `jq`, and `RELAY_OPERATOR_TOKEN` injected from the relay service's
secret configuration. Replace `relay:8080` with the internal service address.
Use a private directory for the code file and keep shell tracing off.

```sh
set -eu
umask 077
secret_dir=$(mktemp -d)
printf 'Authorization: Bearer %s\n' "$RELAY_OPERATOR_TOKEN" |
  curl --fail --silent --show-error --header @- \
    --header 'Content-Type: application/json' \
    --data '{"origin":"https://analyzer.example.org"}' \
    http://relay:8080/v1/operator/enrollment-codes |
  jq -e -r -j '.code | strings | gsub("[[:space:]]"; "")' > "$secret_dir/enrollment-code"
```

Give the code to the analyzer admin through a secret-sharing channel and
remove the temporary code file after the exchange. Treat codes and sender
credentials as secrets. Keep them out of terminals, logs, shell history and
source control. Capture the fields from the JSON response, strip whitespace
and newlines, and write the values directly to private secret storage. Put
the sender credential in the CoreScope service's secret configuration.

## Enroll an analyzer

1. Call `POST /v1/operator/enrollment-codes` with the operator bearer
   credential. The origin must match the analyzer's public `publicBaseUrl`
   origin (scheme, hostname and port if present).

   Request

   ```json
   {"origin":"https://analyzer.example.org"}
   ```

   Response (HTTP 201)

   ```json
   {"code":"<enrollment-code>"}
   ```

2. Exchange the code at `POST /v1/analyzers/enroll`. The `request_id` must
   contain 1–128 characters from `[A-Za-z0-9_-]`.

   Request

   ```json
   {"code":"<enrollment-code>","request_id":"staging-enrollment-1"}
   ```

   Response (HTTP 201)

   ```json
   {"analyzer_id":"<analyzer-id>","sender_credential":"<sender-credential>"}
   ```

3. Verify with `GET /v1/analyzer` using the sender credential as a bearer
   token.

   Response (HTTP 200)

   ```json
   {"analyzer_id":"<analyzer-id>","origin":"https://analyzer.example.org","contract_version":1}
   ```

   Use that analyzer ID in CoreScope's
   `userManagement.notifications.nodeScopePush.analyzerId` and pass the
   credential in `CORESCOPE_NODESCOPE_PUSH_CREDENTIAL`.

A code lasts 15 minutes and works once. During exchange, an expired or used
code still in relay state returns HTTP 410 (`inactive_enrollment`). A
well-formed code the relay has no record of returns HTTP 404
(`unknown_enrollment`). The relay can prune code records 24 hours after
they expire. Issuing a code for an origin with
an active analyzer, or exchanging a still-valid unused code for that origin,
returns HTTP 409 (`analyzer_already_enrolled`). Revoke the active analyzer
before enrolling that origin again.

## Self-service enrollment

Set `RELAY_SELF_ENROLL=true` to allow a CoreScope admin to enroll directly
from the CoreScope admin UI. The default leaves the route disabled. The
manual code flow remains available for deployments that cannot make their
proof endpoint publicly reachable.

Expose `POST /v1/analyzers/self-enroll` on the relay. Allow bounded outbound
HTTPS from the relay to public analyzer hosts on port 443. The analyzer
must expose `GET /api/nodescope/enrollment-proof` on the origin configured
in CoreScope, through its HTTPS proxy or tunnel. The relay requires a
public DNS hostname and a valid TLS certificate, verifies the DNS answers
before connecting, and rejects redirects.

When the admin starts enrollment, CoreScope sends the analyzer origin, an
ephemeral Ed25519 public key, and a randomly generated 32-byte sender
credential. The key and credential use unpadded base64url. The relay
generates a fresh 32-byte challenge and fetches
`/api/nodescope/enrollment-proof?challenge=<base64url-challenge>` from
that origin. The response is JSON with a `signature` field containing the
unpadded base64url Ed25519 signature over the decoded challenge bytes.
The relay registers the analyzer only after it verifies the signature.
A successful request returns HTTP 201 with `analyzer_id` and
`sender_credential`, as in the manual flow.

Keep the sender credential private. CoreScope can retry an interrupted
enrollment with the same sender credential and a fresh proof. This returns
the same analyzer ID if the original request succeeded. An origin with an
active enrollment and a different credential returns HTTP 409
(`analyzer_already_enrolled`). Revoke the old analyzer before changing
credentials.

## Revoke an analyzer

Send `DELETE /v1/analyzer` with the analyzer's sender credential as a
bearer token. HTTP 204 confirms that the analyzer and its subscriptions
are revoked and its queued deliveries are cancelled. Subsequent
`GET /v1/analyzer` and valid `POST /v1/deliveries` requests with that
credential return HTTP 410 (`analyzer_inactive`).

There is no operator-side revoke API. If the sender credential is lost,
restore it from your secret store if possible. To clear a lost enrollment
without the credential, stop the relay and start it with a fresh state file.
This resets all enrollments and subscriptions, so re-enroll every analyzer
and register and link its devices again.

## Enable real providers

Set `RELAY_MODE=staging` or `RELAY_MODE=production` and use a fresh state
file for that deployment. The relay refuses to open simulation state in
either mode. Staging and production also refuse to open each other's state.
Supply the following as service configuration.

| Setting | Value |
| --- | --- |
| `RELAY_STATE_KEY` | Independent random 32-byte key encoded as unpadded base64url |
| `RELAY_APNS_TEAM_ID` | Apple Developer Team ID |
| `RELAY_APNS_KEY_ID` | APNs signing key ID |
| `RELAY_APNS_TOPIC` | App bundle ID, defaulting to `com.btdev.nodescope` |
| `RELAY_APNS_KEY_PATH` | Mounted read-only APNs `.p8` signing key |
| `RELAY_FCM_PROJECT_ID` | Firebase project ID for this deployment |
| `RELAY_FCM_SERVICE_ACCOUNT_PATH` | Mounted read-only Firebase service-account JSON |

Use separate values for `RELAY_OPERATOR_TOKEN` and `RELAY_STATE_KEY`.
Keep the state key in the deployment secret store and preserve it across
restarts. A lost state key requires re-enrolling the analyzer and devices.
Allow relay outbound HTTPS to the matching Apple Push Notification service
endpoint, Google OAuth, and FCM. The network proxy in front of the relay still
terminates incoming HTTPS.

The iPhone test build needs the Push Notifications capability and a
development-signed profile that issues a sandbox device token for the relay's
topic. The Android test build needs Firebase configuration for the same
staging project and an FCM token from that app. Register iOS with
`apns/development` and Android with `fcm/staging`.

For the production deployment at `push.nodescope.app`, use the production
APNs key for `com.btdev.nodescope` and a dedicated production Firebase
project with its matching service account. Use separate operator and state
keys from staging. TestFlight device tokens register as `apns/production`.
The Google Play beta should use the production Firebase app configuration
and register as `fcm/production`. Grant notification permission on both
devices before checking delivery and tap-through.

## Exercise the staging contract

1. [Enroll the analyzer](#enroll-an-analyzer).
2. In simulation, register one synthetic installation per platform. For
   real-provider staging, use tokens from the test devices. Call
   `POST /v1/installations` with provider `apns` and environment
   `development`, or provider `fcm` and environment `staging`. Use each
   installation credential to get an analyzer-scoped proof, then submit the
   proof to CoreScope's authenticated device PUT route.
3. Trigger a watched-node transition on the controlled analyzer. CoreScope
   submits it to the relay. Updated analyzers can include an optional
   `node_name` for the APNs and FCM alert text. When it is absent, the alert
   uses generic wording. Tap-through still uses `node_pubkey`.
   In simulation, the worker logs simulated acceptance.
4. In staging, replay the identical `POST /v1/deliveries` request with the
   analyzer's sender credential. The first request returns HTTP 202 with
   `status: "queued"`. An identical replay returns HTTP 200 with the same
   `delivery_id` and current status while the delivery record is retained,
   such as `queued`, `accepted`, `invalid_token`, `rejected`, `expired` or
   `cancelled`. The relay marks a queued delivery `cancelled` when its
   subscription or analyzer is revoked. Replay can show `cancelled` after
   subscription revocation. After analyzer revocation, replay returns HTTP 410
   (`analyzer_inactive`). Changing the payload while keeping the same
   subscription and event IDs returns HTTP 409 (`delivery_conflict`).
5. Unlink or revoke a test subscription and verify that a new delivery for it
   is rejected. Use a separate staging account and data directory from production.

The CoreScope producer and the relay each maintain their own durable queue.
A provider acceptance is separate from OS presentation. End-to-end acceptance
requires seeing the alert on both locked test phones and opening the correct
analyzer and node from each alert. A device may still show an alert the
provider accepted before opt-out.
