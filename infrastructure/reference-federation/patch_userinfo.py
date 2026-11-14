# TEST-ONLY patch of the reference OP (italia/spid-cie-oidc-django, image pinned in
# docker-compose.yml). The upstream UserInfo endpoint signs a JWT containing only "sub" and the
# requested attributes. The SPID/CIE OIDC specification (spid-cie-oidc-docs,
# docs/it/userinfo_endpoint.rst) lists iss, aud, iat and exp in the UserInfo JWT and requires the
# RP to check aud == client_id; the federation-broker enforces iss and aud (fail closed).
# This patch adds those claims to a COPY of the library used only inside the test container.
# It fails loudly if the upstream code changes, so the patch is re-evaluated on image updates.
import pathlib
import sys

target = pathlib.Path(sys.argv[1]) / "spid_cie_oidc/provider/views/userinfo_endpoint.py"
src = target.read_text()
anchor = '        jwt = {"sub": access_token_data["sub"]}\n'
if src.count(anchor) != 1:
    sys.exit(f"patch_userinfo: anchor not found in {target}; review the reference image update")
replacement = (
    '        import time as _time  # TEST-ONLY patch (infrastructure/reference-federation)\n'
    '        _now = int(_time.time())\n'
    '        jwt = {\n'
    '            "sub": access_token_data["sub"],\n'
    '            "iss": issuer.sub,\n'
    '            "aud": token.session.client_id,\n'
    '            "iat": _now,\n'
    '            "exp": _now + 300,\n'
    '        }\n'
)
target.write_text(src.replace(anchor, replacement))
print(f"patch_userinfo: added iss/aud/iat/exp to UserInfo in {target} (TEST ONLY)")
