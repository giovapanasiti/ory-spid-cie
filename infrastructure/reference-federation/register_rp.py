# Registers the platform's federation-broker RPs as descendants of the REFERENCE TEST trust
# anchor (italia/spid-cie-oidc-django demo) and assigns them the "SPID Public SP" profile, so the
# trust anchor issues a trust mark for them. Run inside the ref-ta container through
# `manage.py shell` (see `make reference-up`). DEVELOPMENT ONLY.
#
# In a real federation the RP public keys reach the trust anchor through the operator's
# onboarding procedure, not by fetching them unauthenticated as done here.
import base64
import json
import os
import urllib.request

from spid_cie_oidc.authority.models import (
    FederationDescendant,
    FederationEntityAssignedProfile,
    FederationEntityProfile,
)
from spid_cie_oidc.entity.models import FederationEntityConfiguration

TA_SUB = "http://trust-anchor.localhost:8000"
PROFILE_ID = "https://www.spid.gov.it/openid-federation/agreement/sp-public"
RP_ENTITIES = os.environ.get(
    "REFERENCE_RP_ENTITIES",
    "http://broker.localhost:8090/rp/spid,http://broker.localhost:8090/rp/cie",
).split(",")


def b64url_json(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


ta = FederationEntityConfiguration.objects.get(sub=TA_SUB)
profile = FederationEntityProfile.objects.get(profile_id=PROFILE_ID)

for sub in RP_ENTITIES:
    sub = sub.strip().rstrip("/")
    with urllib.request.urlopen(sub + "/.well-known/openid-federation", timeout=15) as res:
        jws = res.read().decode()
    payload = b64url_json(jws.split(".")[1])
    if payload.get("iss") != sub or payload.get("sub") != sub:
        raise SystemExit(f"entity configuration of {sub} has unexpected iss/sub")
    if TA_SUB not in payload.get("authority_hints", []):
        print(f"WARNING: {sub} does not list {TA_SUB} in authority_hints yet")
    keys = payload["jwks"]["keys"]
    descendant, created = FederationDescendant.objects.update_or_create(
        sub=sub,
        defaults=dict(
            name=("IAM broker " + sub.rsplit("/", 1)[-1])[:33],
            type="openid_relying_party",
            jwks=keys,
            is_active=True,
            status="valid",
        ),
    )
    FederationEntityAssignedProfile.objects.get_or_create(
        descendant=descendant, profile=profile, issuer=ta
    )
    kids = ", ".join(k.get("kid", "?") for k in keys)
    print(f"{'registered' if created else 'updated'} descendant {sub} (keys: {kids}) with profile {PROFILE_ID}")
