

# ---- Overrides appended by infrastructure/reference-federation/entrypoint.sh (TEST ONLY) ----
# The compose network uses private addresses (172.16.0.0/12): allow federation fetches to them.
# Loopback and link-local addresses stay refused by the library.
OIDCFED_FETCH_PRIVATE_NETS = True
