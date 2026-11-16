# Biptec patch to gokrb5 v8.4.4

This directory is a source-preserving local replacement for
`github.com/jcmturner/gokrb5/v8@v8.4.4`.

## Upstream provenance

- Upstream: https://github.com/jcmturner/gokrb5
- Version: `v8.4.4`
- Upstream commit: `47cd2e7744531465a983bf457bac38e6ad8f4684`
- Upstream license: Apache-2.0 (see the unmodified `LICENSE` file).

The provider's root `go.mod` replaces the upstream module with this directory.
The upstream package tree, license, and tests are retained. Trailing
whitespace was normalized in the vendored text files to satisfy the downstream
repository's diff checks; this is formatting-only and does not change upstream
behavior. The fork's module metadata declares Go 1.18 (the minimum version
providing `net/netip`) and records the indirect dependencies required by the
retained test suite. The upstream Apache-2.0 license remains unchanged.

## Local change

The only intended upstream source change is in `client/network.go`:

- resolve every configured KDC hostname to all available A and AAAA addresses;
- resolve configured KDC alternatives concurrently within a one-second DNS window, so a stalled lookup for one KDC does not block another resolved KDC;
- preserve configured KDC preference order among the addresses resolved within that window;
- attempt candidate addresses with a 250 ms stagger, accepting the first KDC response;
- use one five-second deadline for resolution and all address/KDC attempts, for both UDP and TCP;
- close losing sockets when the successful attempt cancels the shared context.

This removes the previous single-address `ResolveUDPAddr` / `ResolveTCPAddr`
selection and prevents serial five-second timeouts from accumulating for each
address and KDC. Kerberos request encoding, authentication, KDC preference
ordering, UDP/TCP size fallback, and response validation remain upstream-owned.

## Updating the fork

When upgrading gokrb5, start from the exact new upstream module source and
reapply only the network transport patch. Do not hand-merge unrelated upstream
changes. Run both this module's tests and the parent provider's complete test
suite before changing the pinned upstream version.
