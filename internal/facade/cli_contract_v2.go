package facade

import "context"

// executeTrustV2 keeps the /2 commands separate from seal/anchor wiring and
// reuses the existing strict long-option parser and closed result envelope.
func executeTrustV2(ctx context.Context, command string, args []string) (string, any, *Failure) {
	names := []string{"request"}
	if command == "grant draft-v2" {
		names = append(names, "config", "seal-ledger")
	}
	o, f := keychainOptions(args, names...)
	if f != nil {
		return "", nil, f
	}
	if command == "grant contract-verify" {
		var r ContractVerifyV2Request
		if f := inputFile(o["request"], &r); f != nil {
			return "", nil, f
		}
		if r.Schema != ContractVerifyV2Schema {
			return "", nil, fail("BAD_INPUT")
		}
		raw, code := decodeContractV2B64(r.ContractB64)
		if code != "" {
			return "", nil, refuse(code)
		}
		text, code := decodeScopeTextV2(r.ScopeTextB64)
		if code != "" {
			return "", nil, refuse(code)
		}
		c, code := VerifyTrustContractV2(raw, text, r.IssuerKey, r.LandlordSig)
		if code != "" {
			return "", nil, refuse(code)
		}
		return c.Network, &ContractVerifyV2Result{c, sha256Hex(raw), true, r.ScopeTextB64}, nil
	}
	var r GrantDraftV2Request
	if f := inputFile(o["request"], &r); f != nil {
		return "", nil, f
	}
	var config Config
	if f := inputFile(o["config"], &config); f != nil {
		return "", nil, f
	}
	network := selectedNetwork(config.Network)
	c, f := NewClient(config)
	if f != nil {
		return network, nil, f
	}
	defer c.Close()
	result, f := c.DraftGrantV2(ctx, r, o["seal-ledger"])
	return network, result, f
}
