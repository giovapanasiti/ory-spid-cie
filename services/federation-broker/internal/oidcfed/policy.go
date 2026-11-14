package oidcfed

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// Metadata policy operators defined by OpenID Federation 1.0 §6.1.3.1.
var supportedOperators = map[string]bool{
	"value": true, "add": true, "default": true, "one_of": true,
	"subset_of": true, "superset_of": true, "essential": true,
}

// Policy is the policy for one entity type: claim -> operator -> value.
type Policy map[string]map[string]any

// MergePolicies combines a superior policy with a subordinate one (top-down),
// failing when the combination is not allowed by the specification.
func MergePolicies(sup, sub Policy) (Policy, error) {
	out := Policy{}
	for claim, ops := range sup {
		out[claim] = cloneOps(ops)
	}
	for claim, ops := range sub {
		for op := range ops {
			if !supportedOperators[op] {
				return nil, fmt.Errorf("unsupported metadata policy operator %q", op)
			}
		}
		cur, ok := out[claim]
		if !ok {
			out[claim] = cloneOps(ops)
			continue
		}
		merged, err := mergeOps(claim, cur, ops)
		if err != nil {
			return nil, err
		}
		out[claim] = merged
	}
	for claim, ops := range out {
		if err := checkOps(claim, ops); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func cloneOps(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeOps(claim string, a, b map[string]any) (map[string]any, error) {
	out := cloneOps(a)
	for op, bv := range b {
		av, exists := out[op]
		if !exists {
			out[op] = bv
			continue
		}
		switch op {
		case "value", "default":
			if !jsonEqual(av, bv) {
				return nil, fmt.Errorf("policy conflict on %s.%s", claim, op)
			}
		case "add", "superset_of":
			out[op] = union(toList(av), toList(bv))
		case "one_of", "subset_of":
			inter := intersect(toList(av), toList(bv))
			if len(inter) == 0 {
				return nil, fmt.Errorf("policy conflict on %s.%s: empty intersection", claim, op)
			}
			out[op] = inter
		case "essential":
			ab, _ := av.(bool)
			bb, _ := bv.(bool)
			out[op] = ab || bb
		}
	}
	return out, nil
}

// checkOps verifies operator combinations within a merged policy entry.
func checkOps(claim string, ops map[string]any) error {
	if sub, ok := ops["subset_of"]; ok {
		if sup, ok := ops["superset_of"]; ok {
			if !isSubset(toList(sup), toList(sub)) {
				return fmt.Errorf("policy conflict on %s: superset_of not within subset_of", claim)
			}
		}
		if add, ok := ops["add"]; ok && !isSubset(toList(add), toList(sub)) {
			return fmt.Errorf("policy conflict on %s: add not within subset_of", claim)
		}
	}
	if v, ok := ops["value"]; ok && v != nil {
		if one, ok := ops["one_of"]; ok && !contains(toList(one), v) {
			return fmt.Errorf("policy conflict on %s: value not in one_of", claim)
		}
	}
	return nil
}

// ApplyPolicy applies a merged policy to metadata, returning a new map.
func ApplyPolicy(md map[string]any, p Policy) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range md {
		out[k] = v
	}
	claims := make([]string, 0, len(p))
	for c := range p {
		claims = append(claims, c)
	}
	sort.Strings(claims)
	for _, claim := range claims {
		ops := p[claim]
		val, present := out[claim]
		if v, ok := ops["value"]; ok {
			if v == nil {
				delete(out, claim)
				present = false
			} else {
				out[claim] = v
				val, present = v, true
			}
		}
		if add, ok := ops["add"]; ok {
			if present {
				val = union(toList(val), toList(add))
			} else {
				val = toList(add)
			}
			out[claim] = val
			present = true
		}
		if def, ok := ops["default"]; ok && !present {
			out[claim] = def
			val, present = def, true
		}
		if ess, ok := ops["essential"].(bool); ok && ess && !present {
			return nil, fmt.Errorf("metadata claim %q is essential but absent", claim)
		}
		if !present {
			continue
		}
		if one, ok := ops["one_of"]; ok {
			if !contains(toList(one), val) {
				return nil, fmt.Errorf("metadata claim %q value not allowed by one_of", claim)
			}
		}
		if sub, ok := ops["subset_of"]; ok {
			inter := intersect(toList(val), toList(sub))
			if len(inter) == 0 {
				// Per spec the claim is removed; if essential this is an error.
				if ess, _ := ops["essential"].(bool); ess {
					return nil, fmt.Errorf("metadata claim %q empty after subset_of", claim)
				}
				delete(out, claim)
				continue
			}
			out[claim] = inter
			val = inter
		}
		if sup, ok := ops["superset_of"]; ok {
			if !isSubset(toList(sup), toList(val)) {
				return nil, fmt.Errorf("metadata claim %q does not satisfy superset_of", claim)
			}
		}
	}
	return out, nil
}

func toList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	case nil:
		return nil
	default:
		return []any{t}
	}
}

func jsonEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return reflect.DeepEqual(ja, jb)
}

func contains(list []any, v any) bool {
	for _, x := range list {
		if jsonEqual(x, v) {
			return true
		}
	}
	return false
}

func union(a, b []any) []any {
	out := append([]any{}, a...)
	for _, x := range b {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func intersect(a, b []any) []any {
	out := []any{}
	for _, x := range a {
		if contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func isSubset(a, b []any) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}
