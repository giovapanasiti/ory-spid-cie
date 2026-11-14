# Reference test federation (italia/spid-cie-oidc-django)

The local simulator `fedsim` was written together with the broker, so a test passing against it shows
that the two pieces agree with each other, not that the broker interoperates with someone else's code.
The reference test federation closes part of that gap: the broker talks to the **official reference
implementation** published by Developers Italia, [`italia/spid-cie-oidc-django`](https://github.com/italia/spid-cie-oidc-django),
running its demo projects in local containers.

> **Test only.** The demo projects use public keys, public users (`user` / `oidcuser`) and the Django
> development server. They are bound to `127.0.0.1` and enabled only by an explicit command. Passing
> tests against them is **interoperability evidence against the reference code, not conformance**:
> no AgID or Ministero dell'Interno environment is involved.

## Why not demo.spid.gov.it

`https://demo.spid.gov.it` is the AgID demo environment for **SAML 2.0** only (IdP entityID
`https://demo.spid.gov.it`, metadata `/metadata.xml`, SP registration through the SPID SAML Validator).
On 2026-11-14 its OpenID Federation paths (`/.well-known/openid-federation`,
`/.well-known/openid-configuration`) returned the Validator HTML page and no metadata. The platform
implements SPID through OpenID Connect Federation only, so it cannot use that environment. Official
OIDC test paths (AgID SPID OIDC validator, CIE pre-production through the Federation portal) need a
public URL and the organisation's onboarding: see [`onboarding.md`](onboarding.md).

## What runs

| Container | Image project | Entity | Browser URL |
|---|---|---|---|
| `ref-ta` | `examples/federation_authority` | Trust Anchor `http://trust-anchor.localhost:8000` and SPID OP `http://trust-anchor.localhost:8000/oidc/op` | http://trust-anchor.localhost:8000 |
| `ref-cie-op` | `examples/provider` | CIE OP `http://cie-provider.localhost:8002/oidc/op` | http://cie-provider.localhost:8002 |

The image is `ghcr.io/italia/spid-cie-oidc-django`, pinned by digest in
`infrastructure/docker/docker-compose.yml` (published 2026-11-09, linux/amd64 only: it runs emulated on
arm64 hosts). The demo projects are copied from the image at start, so no upstream code is vendored in
this repository.

### Host names

Every entity ID must work for two clients: the browser on the host and the containers on the compose
network. Names under `.localhost` do both without touching `/etc/hosts`:

- browsers resolve `*.localhost` to the loopback address (RFC 6761), where the published ports are;
- inside the compose network the same names are Docker network aliases of the containers
  (`trust-anchor.localhost`, `cie-provider.localhost`, `broker.localhost`).

For the same reason the broker's public URL is `http://broker.localhost:8090` and its local entity IDs
are `http://broker.localhost:8090/rp/{spid,cie}`. The reference OP refuses an authorization request
whose `redirect_uri` host is not contained in the `client_id`, so the entity ID and the callback must
share one host name.

## Usage

```bash
make dev             # platform (once)
make reference-up    # start ref-ta and ref-cie-op, register the broker, configure trust
make test-e2e-reference
make reference-down  # stop the reference containers (broker configuration is kept)
```

`make reference-up` performs three steps:

1. starts `ref-ta` and `ref-cie-op` (`infrastructure/reference-federation/entrypoint.sh`);
2. registers the two broker RPs as descendants of the reference Trust Anchor and assigns them the
   "SPID Public SP" profile, so the Trust Anchor issues a trust mark
   (`infrastructure/reference-federation/register_rp.py`);
3. configures the broker through its admin API (`scripts/seed-reference.mjs`): pins the reference Trust
   Anchor for both profiles, adds it to the `authority_hints`, installs its trust mark and adds the two
   OPs as identity providers. `fedsim` stays configured, so both federations work side by side.

The Trust Anchor database lives in a tmpfs: every `reference-up` after a `reference-down` starts from
the demo data and repeats the registration.

Manual login: open http://localhost:5580, choose **Accedi**, then **Accedi con SPID** and **SPID OP di
riferimento**, or **Entra con CIE** and **CIE OP di riferimento**. On the OP use `user` / `oidcuser` and
accept the consent page.

## What the tests exercise

`tests/e2e/reference/reference.spec.ts`:

| Test | Path through the broker |
|---|---|
| SPID login via the reference SPID OP | trust chain OP → reference TA, metadata policy, signed request object, PKCE, `private_key_jwt`, ID token validation, signed and encrypted UserInfo, attribute normalisation, `SpidL2` → `urn:iam:loa:substantial`, fiscal number released with the `fiscal_number` scope |
| CIE login (step-up to high) via the reference CIE OP | as above with `SpidL3` → `urn:iam:loa:high`, then the demo API accepts the high-assurance call |

Result on 2026-11-14: 2 passed, with the two test-only adjustments described below.

## Findings

| # | Finding | Handling |
|---|---|---|
| 1 | The reference OP signs a UserInfo JWT that contains only `sub` and the requested attributes. The specification (`spid-cie-oidc-docs`, `docs/it/userinfo_endpoint.rst`) lists `iss`, `aud`, `iat` and `exp`, and requires the RP to check that `aud` is its `client_id`. The broker rejects the response (`userinfo issuer mismatch`). | Broker unchanged (fail closed). `infrastructure/reference-federation/patch_userinfo.py` adds the four claims to a **copy** of the library inside the test container; the start fails if the patched code changes upstream. Worth reporting upstream. |
| 2 | The demo user `user` has fiscal number `TINIT-AATTTJDFKSKDF89`, 15 characters, which is not a valid codice fiscale. The broker drops it as malformed and the login fails with `missing_attributes`. | The entrypoint replaces it in the loaded fixture with synthetic, well-formed codes (`RSSNTN80R10F839Z` on the SPID OP, `MRDPPP90R10F839Y` on the CIE OP). |
| 3 | The reference OP requires the `redirect_uri` host to appear in the `client_id`. | Broker public URL and entity IDs moved to `broker.localhost` (see Host names). |
| 4 | OPs issue pairwise subjects per RP. Changing the RP entity ID gives every user a new subject, so existing links no longer match and Kratos treats returning users as new federated identities (an existing email triggers its account-linking flow). | Expected behaviour. In production the entity ID must be treated as permanent; see [`../operations/runbook.md`](../operations/runbook.md). |
| 5 | With two federations configured, the broker's self-check built its own chain through the first trust anchor (`fedsim`) and reported the reference trust mark as "issuer not authorised". | Broker fix: a trust mark issued by another **pinned** trust anchor belongs to that federation and is ignored in the current chain (neither verified nor an error). Unit test `internal/oidcfed/trustmark_test.go`. |

## Limits

- The reference projects run the Django development server with `DEBUG = True`, sqlite and public demo
  keys; they say nothing about the behaviour of production OPs.
- The Trust Anchor learns the broker's federation keys by fetching its entity configuration; real
  onboarding delivers them through the operator's procedure.
- The broker pins the reference Trust Anchor keys from its entity configuration without out-of-band
  verification. This is acceptable only because the Trust Anchor is a local container built from the
  pinned official image.
- Only the success paths above are automated; error scenarios stay covered by `fedsim`.
