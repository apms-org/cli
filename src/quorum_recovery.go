package apm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func gfAdd(a, b byte) byte { return a ^ b }

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		hi := (a & 0x80) != 0
		a <<= 1
		if hi {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func gfPow(a byte, power int) byte {
	res := byte(1)
	for i := 0; i < power; i++ {
		res = gfMul(res, a)
	}
	return res
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfPow(a, 254)
}

func splitSecretShamir(secret []byte, shares, threshold int) ([][]byte, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if shares < threshold || shares > 255 {
		return nil, errors.New("shares must be >= threshold and <= 255")
	}
	out := make([][]byte, shares)
	for i := 0; i < shares; i++ {
		out[i] = make([]byte, len(secret)+1)
		out[i][0] = byte(i + 1)
	}

	coeff := make([]byte, threshold)
	for pos, secretByte := range secret {
		coeff[0] = secretByte
		if _, err := rand.Read(coeff[1:]); err != nil {
			return nil, err
		}
		for s := 0; s < shares; s++ {
			x := byte(s + 1)
			y := coeff[0]
			xPow := byte(1)
			for p := 1; p < threshold; p++ {
				xPow = gfMul(xPow, x)
				y = gfAdd(y, gfMul(coeff[p], xPow))
			}
			out[s][pos+1] = y
		}
	}
	return out, nil
}

func combineSecretShamir(parts [][]byte, threshold int) ([]byte, error) {
	if len(parts) < threshold {
		return nil, errors.New("not enough shares provided")
	}

	used := map[byte]bool{}
	filtered := make([][]byte, 0, threshold)
	var payloadLen int
	for _, p := range parts {
		if len(p) < 2 {
			return nil, errors.New("invalid share")
		}
		if payloadLen == 0 {
			payloadLen = len(p) - 1
		}
		if len(p)-1 != payloadLen {
			return nil, errors.New("share length mismatch")
		}
		x := p[0]
		if x == 0 || used[x] {
			continue
		}
		used[x] = true
		filtered = append(filtered, p)
		if len(filtered) == threshold {
			break
		}
	}
	if len(filtered) < threshold {
		return nil, errors.New("not enough distinct shares")
	}

	secret := make([]byte, payloadLen)
	for pos := 0; pos < payloadLen; pos++ {
		var val byte
		for j := 0; j < threshold; j++ {
			xj := filtered[j][0]
			yj := filtered[j][pos+1]

			num := byte(1)
			den := byte(1)
			for m := 0; m < threshold; m++ {
				if m == j {
					continue
				}
				xm := filtered[m][0]
				num = gfMul(num, xm)
				den = gfMul(den, gfAdd(xm, xj))
			}
			if den == 0 {
				return nil, errors.New("invalid share set")
			}
			lagrange := gfMul(num, gfInv(den))
			val = gfAdd(val, gfMul(yj, lagrange))
		}
		secret[pos] = val
	}

	return secret, nil
}

func formatRecoveryShare(index int, bytes []byte) string {
	return fmt.Sprintf("QSHARE-%d-%s", index, strings.ToUpper(hex.EncodeToString(bytes)))
}

func parseRecoveryShare(share string) (int, []byte, error) {
	parts := strings.Split(strings.TrimSpace(share), "-")
	if len(parts) < 3 || strings.ToUpper(parts[0]) != "QSHARE" {
		return 0, nil, errors.New("invalid share format")
	}
	idx, err := strconv.Atoi(parts[1])
	if err != nil || idx <= 0 {
		return 0, nil, errors.New("invalid share index")
	}
	raw, err := hex.DecodeString(parts[2])
	if err != nil {
		return 0, nil, errors.New("invalid share payload")
	}
	return idx, raw, nil
}

func SetupRecoveryQuorum(v *Vault, threshold, shares int) (map[int]string, error) {
	return SetupRecoveryQuorumWithKey(v, "", threshold, shares)
}

func normalizeRecoveryCandidate(key string) string {
	return strings.ToUpper(strings.TrimSpace(key))
}

func resolveRecoveryKeyForQuorum(v *Vault, provided string) (string, error) {
	candidates := []string{}
	if k := normalizeRecoveryCandidate(provided); k != "" {
		candidates = append(candidates, k)
	}
	if k := normalizeRecoveryCandidate(v.RawRecoveryKey); k != "" {
		candidates = append(candidates, k)
	}
	if len(v.ObfuscatedKey) > 0 {
		if k := normalizeRecoveryCandidate(DeObfuscateRecoveryKey(v.ObfuscatedKey)); k != "" {
			candidates = append(candidates, k)
		}
	}

	if len(v.RecoveryHash) > 0 && len(v.RecoverySalt) > 0 {
		for _, c := range candidates {
			// Try Argon2id-based derivation first, then legacy SHA-256
			if _, ok := tryDeriveRecoveryKey(deriveRecoveryKeyArgon2, c, v.RecoverySalt, v.RecoveryHash); ok {
				return c, nil
			}
			if _, ok := tryDeriveRecoveryKey(deriveRecoveryKeyLegacy, c, v.RecoverySalt, v.RecoveryHash); ok {
				return c, nil
			}
		}
		if normalizeRecoveryCandidate(provided) != "" {
			return "", errors.New("provided recovery key does not match this vault")
		}
		return "", errors.New("recovery key is not auto-available; provide the recovery key explicitly")
	}

	if len(candidates) > 0 {
		return candidates[0], nil
	}
	return "", errors.New("recovery key is not configured; run 'pm auth email <address>' first")
}

func SetupRecoveryQuorumWithKey(v *Vault, recoveryKey string, threshold, shares int) (map[int]string, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if shares < threshold {
		return nil, fmt.Errorf("share count must be >= threshold")
	}

	recoveryKey, err := resolveRecoveryKeyForQuorum(v, recoveryKey)
	if recoveryKey == "" {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("recovery key is not configured; run 'pm auth email <address>' first")
	}

	chunks, err := splitSecretShamir([]byte(recoveryKey), shares, threshold)
	if err != nil {
		return nil, err
	}

	v.RecoveryShareThreshold = threshold
	v.RecoveryShareCount = shares
	v.RecoveryShareHashes = map[string][]byte{}

	out := make(map[int]string, shares)
	for i, c := range chunks {
		share := formatRecoveryShare(i+1, c)
		h := sha256.Sum256([]byte(share))
		v.RecoveryShareHashes[strconv.Itoa(i+1)] = h[:]
		out[i+1] = share
	}

	return out, nil
}

func CombineRecoveryQuorumShares(v *Vault, shares []string) (string, error) {
	if v.RecoveryShareThreshold < 2 || len(v.RecoveryShareHashes) == 0 {
		return "", errors.New("recovery quorum is not configured")
	}

	rawParts := make([][]byte, 0, len(shares))
	used := map[int]bool{}
	for _, share := range shares {
		idx, raw, err := parseRecoveryShare(share)
		if err != nil {
			return "", err
		}
		if used[idx] {
			continue
		}
		h := sha256.Sum256([]byte(strings.TrimSpace(share)))
		expected, ok := v.RecoveryShareHashes[strconv.Itoa(idx)]
		if !ok || hex.EncodeToString(expected) != hex.EncodeToString(h[:]) {
			return "", fmt.Errorf("share %d failed verification", idx)
		}
		used[idx] = true
		rawParts = append(rawParts, raw)
	}

	sort.Slice(rawParts, func(i, j int) bool {
		return rawParts[i][0] < rawParts[j][0]
	})

	secret, err := combineSecretShamir(rawParts, v.RecoveryShareThreshold)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}
