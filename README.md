# v0.0.120-codex production identity gate

This owned module version runs one bounded, read-only identity check from the
exact Capslock compiler lane for `v0.0.120-codex`.

The callback can select only compiled typed probes. The production batch is:

1. record the exact lane, uid/gid, cwd, PID 1, and namespace relationship;
2. if the standard projected Kubernetes identity exists, call `/version` and
   a fixed set of `SelfSubjectAccessReview` checks; and
3. use the mounted client certificate in place to call only gRPC Health and
   Server Reflection on the fixed Talisman endpoint.

The Kubernetes receipt contains the namespace and these decoded JWT claims
only: subject, issuer, audience, expiry, and pod name/uid. It never returns the
raw token, JWT header or signature, a token hash, authorization reasons, or API
resource contents. SSAR responses are reduced to fixed check IDs and
allowed/denied/status booleans.

The mTLS receipt contains the client certificate subject, issuer, DNS SANs,
validity period, and SHA-256 fingerprint. It never returns the certificate or
private-key bytes. Reflection output is reduced to the presence of six fixed
service names.

Each operation has a five-second deadline. Responses are size-bounded, the
session has a ten-minute and thirty-step ceiling, and requests/results are
bound into a nonce-authenticated rolling transcript hash. The client has no
shell, arbitrary URL, arbitrary gRPC method, Kubernetes resource read/list,
metadata-token, credential-export, persistence, or Queue mutation interface.

This tag is separate from the owned A-to-B Queue canary. It does not touch that
canary or depend on its cleanup state.
