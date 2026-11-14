#!/bin/sh
# REFERENCE TEST federation (italia/spid-cie-oidc-django demo projects). DEVELOPMENT ONLY.
# Copies one example project shipped in the image, rewrites its 127.0.0.1 URLs to
# *.localhost hostnames (resolved to 127.0.0.1 by browsers and to the containers by the
# compose network aliases), loads the demo data and starts the Django server.
# The demo keys and users are public: never use this outside an isolated local environment.
set -eu
PROJECT="$1"
PORT="$2"
SRC="/opt/examples/${PROJECT}"
WORK="/work/${PROJECT}"
[ -d "$SRC" ] || { echo "unknown example project: $PROJECT" >&2; exit 1; }

# TEST-ONLY patch of a copy of the library (see patch_userinfo.py); PYTHONPATH makes the copy
# take precedence over the package installed in the image.
rm -rf /work/pylib
mkdir -p /work/pylib
cp -R /opt/spid_cie_oidc /work/pylib/spid_cie_oidc
python3 /reference/patch_userinfo.py /work/pylib
export PYTHONPATH=/work/pylib

rm -rf "$WORK"
cp -R "$SRC" "$WORK"
cd "$WORK"
rm -f db.sqlite3

SUBS='s,http://127.0.0.1:8000,http://trust-anchor.localhost:8000,g;s,http://127.0.0.1:8001,http://relying-party.localhost:8001,g;s,http://127.0.0.1:8002,http://cie-provider.localhost:8002,g'
sed -e "$SUBS" dumps/example.json > dumps/example.local.json
# TEST-ONLY fixture fix: the demo user "user" has fiscal number "TINIT-AATTTJDFKSKDF89"
# (15 characters, not a valid codice fiscale), which the broker rejects as malformed.
# Replace it with a synthetic, well-formed code (correct check character) matching the demo
# user's name, birth date and place.
case "$PROJECT" in
  federation_authority) CF=RSSNTN80R10F839Z ;;  # antonio rossi, 1980-10-10, F839
  provider) CF=MRDPPP90R10F839Y ;;              # peppe maradona, 1990-10-10, F839
  *) CF="" ;;
esac
[ -z "$CF" ] || sed -i "s/TINIT-AATTTJDFKSKDF89/TINIT-${CF}/g" dumps/example.local.json
sed -e "$SUBS" "${PROJECT}/settingslocal.py.example" > "${PROJECT}/settingslocal.py"
cat /reference/settings_overrides.py >> "${PROJECT}/settingslocal.py"

python3 manage.py migrate --noinput >/dev/null
python3 manage.py loaddata dumps/example.local.json
echo "reference federation project ${PROJECT} ready on port ${PORT} (TEST ONLY)"
exec python3 manage.py runserver "0.0.0.0:${PORT}" --noreload
