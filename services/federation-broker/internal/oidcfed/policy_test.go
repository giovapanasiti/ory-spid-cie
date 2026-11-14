package oidcfed

import (
	"testing"
)

func TestApplyPolicyOperators(t *testing.T) {
	md := map[string]any{
		"grant_types":    []any{"authorization_code", "refresh_token", "implicit"},
		"response_types": []any{"code"}, "id_token_signed_response_alg": "RS256",
		"contacts": []any{"a@example.org"},
	}
	p := Policy{
		"grant_types":                  {"subset_of": []any{"authorization_code", "refresh_token"}},
		"contacts":                     {"add": []any{"ops@example.org"}},
		"client_name":                  {"default": "Default RP"},
		"id_token_signed_response_alg": {"one_of": []any{"RS256", "ES256"}},
		"token_endpoint_auth_method":   {"value": "private_key_jwt"},
	}
	out, err := ApplyPolicy(md, p)
	if err != nil {
		t.Fatal(err)
	}
	if got := out["grant_types"].([]any); len(got) != 2 {
		t.Fatalf("subset_of not applied: %v", got)
	}
	if got := out["contacts"].([]any); len(got) != 2 {
		t.Fatalf("add not applied: %v", got)
	}
	if out["client_name"] != "Default RP" || out["token_endpoint_auth_method"] != "private_key_jwt" {
		t.Fatalf("default/value not applied: %v", out)
	}
}

func TestApplyPolicyRejections(t *testing.T) {
	cases := map[string]struct {
		md map[string]any
		p  Policy
	}{
		"essential missing":         {map[string]any{}, Policy{"jwks": {"essential": true}}},
		"one_of violated":           {map[string]any{"alg": "HS256"}, Policy{"alg": {"one_of": []any{"RS256", "ES256"}}}},
		"superset_of":               {map[string]any{"x": []any{"a"}}, Policy{"x": {"superset_of": []any{"a", "b"}}}},
		"subset_of empty essential": {map[string]any{"x": []any{"z"}}, Policy{"x": {"subset_of": []any{"a"}, "essential": true}}},
	}
	for name, c := range cases {
		if _, err := ApplyPolicy(c.md, c.p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMergePolicies(t *testing.T) {
	sup := Policy{"scopes": {"subset_of": []any{"openid", "email", "profile"}}, "v": {"value": "x"}}
	sub := Policy{"scopes": {"subset_of": []any{"openid", "profile", "phone"}}}
	m, err := MergePolicies(sup, sub)
	if err != nil {
		t.Fatal(err)
	}
	if got := m["scopes"]["subset_of"].([]any); len(got) != 2 {
		t.Fatalf("intersection expected, got %v", got)
	}
	if _, err := MergePolicies(sup, Policy{"v": {"value": "y"}}); err == nil {
		t.Fatal("conflicting value must fail")
	}
	if _, err := MergePolicies(sup, Policy{"scopes": {"subset_of": []any{"nope"}}}); err == nil {
		t.Fatal("empty intersection must fail")
	}
	if _, err := MergePolicies(sup, Policy{"x": {"regexp": "^a"}}); err == nil {
		t.Fatal("unknown operator must fail")
	}
}
