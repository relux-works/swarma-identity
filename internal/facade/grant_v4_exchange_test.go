package facade

import (
	"encoding/json"
	"fmt"
	"testing"
)

func v4ExchangeMap(t *testing.T, r any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("exchange fixture")
	}
	return out
}

// TestV4ConsentExplicitTime proves missing/null times have no default and out-of-range explicit times refuse CONSENT_SHAPE, beside both inclusive valid edges.
func TestV4ConsentExplicitTime(t *testing.T) {
	for _, pair := range []struct {
		good int64
		bad  any
		code string
	}{{1, nil, "BAD_INPUT"}, {1, "absent", "BAD_INPUT"}, {1, int64(0), "CONSENT_SHAPE"}, {2, int64(-1), "CONSENT_SHAPE"}, {253402300799, int64(253402300800), "CONSENT_SHAPE"}, {253402300798, int64(253402300801), "CONSENT_SHAPE"}} {
		t.Run(fmt.Sprint(pair.bad), func(t *testing.T) {
			r := v4ExchangeMap(t, v4Request(t, "grant-v-01"))
			r["created_at"] = pair.good
			e, exit := v4CLI(t, "grant consent-v4", r)
			mustOK(t, e, exit)
			r["created_at"] = pair.bad
			if pair.bad == "absent" {
				delete(r, "created_at")
			}
			e, exit = v4CLI(t, "grant consent-v4", r)
			mustRefuse(t, e, exit, pair.code)
			if e.Result != nil {
				t.Fatal("invalid time returned a template")
			}
		})
	}
}

// TestV4ExchangePresence proves empty cross-stage members still refuse BAD_INPUT and anchor clocks must be explicit, beside valid stage requests.
func TestV4ExchangePresence(t *testing.T) {
	for _, command := range []string{"grant draft-v4", "grant sign-v4", "grant consent-v4", "grant anchor-v4"} {
		for _, field := range []string{"signature", "signed_hex", "now", "created_at"} {
			allowed := (command == "grant sign-v4" && field == "signature") || (command == "grant consent-v4" && field == "created_at") || (command == "grant anchor-v4" && (field == "signed_hex" || field == "now"))
			if allowed {
				continue
			}
			t.Run(command+"/"+field, func(t *testing.T) {
				r := v4Request(t, "grant-v-01")
				if command == "grant sign-v4" {
					g, _ := v4Grant(t, "grant-v-01")
					r.Signature = g.Signature()
				}
				if command == "grant consent-v4" {
					r.CreatedAt = 1
				}
				if command == "grant anchor-v4" {
					r, _ = v4PreparationControl(t)
				}
				m := v4ExchangeMap(t, r)
				e, exit := v4CLI(t, command, m)
				mustOK(t, e, exit)
				m[field] = ""
				if field == "now" || field == "created_at" {
					m[field] = 0
				}
				e, exit = v4CLI(t, command, m)
				mustRefuse(t, e, exit, "BAD_INPUT")
				if e.Result != nil {
					t.Fatal("cross-stage member returned a result")
				}
			})
		}
	}
	for _, value := range []any{"absent", nil} {
		r, _ := v4PreparationControl(t)
		m := v4ExchangeMap(t, r)
		e, exit := v4CLI(t, "grant anchor-v4", m)
		mustOK(t, e, exit)
		m["now"] = value
		if value == "absent" {
			delete(m, "now")
		}
		e, exit = v4CLI(t, "grant anchor-v4", m)
		mustRefuse(t, e, exit, "BAD_INPUT")
		if e.Result != nil {
			t.Fatal("missing clock returned a preparation")
		}
	}
}
