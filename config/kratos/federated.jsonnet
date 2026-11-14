// Maps claims from the federation broker facade (SPID / CIE) to Kratos traits.
// Only self-asserted, user-editable traits are set here. Verified attributes
// (fiscal code, birthdate, ...) are stored by identity-service with provenance
// and are NOT copied into traits (data minimisation, no user tampering).
// The fiscal code is never sent to Kratos.
local claims = std.extVar('claims');
local has(k) = std.objectHas(claims, k) && claims[k] != null && claims[k] != '';
{
  identity: {
    traits: {
      [if has('email') then 'email']: claims.email,
      name: {
        [if has('given_name') then 'first']: claims.given_name,
        [if has('family_name') then 'last']: claims.family_name,
      },
    },
  },
}
