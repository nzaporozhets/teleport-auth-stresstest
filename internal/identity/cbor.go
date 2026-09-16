package identity

// Minimal CBOR (RFC 8949) encoder covering only what the soft WebAuthn
// authenticator needs to build: a COSE_Key map and a WebAuthn
// AttestationObject map, both fixed, small shapes. Hand-rolled instead of
// pulling in a general CBOR library (fxamacker/cbor) — see
// docs/methodology.md for the rationale (avoid an extra dependency for
// two fixed struct encodes; verified against a real WebAuthn parser in
// webauthn_soft_test.go, not just round-tripped against itself).

func cborUint(v uint64) []byte {
	return cborHead(0, v)
}

// cborNegInt encodes a negative integer n (n must be < 0) per CBOR major
// type 1: the wire value is -1-n.
func cborNegInt(n int64) []byte {
	return cborHead(1, uint64(-1-n))
}

func cborHead(majorType byte, v uint64) []byte {
	major := majorType << 5
	switch {
	case v < 24:
		return []byte{major | byte(v)}
	case v <= 0xff:
		return []byte{major | 24, byte(v)}
	case v <= 0xffff:
		return []byte{major | 25, byte(v >> 8), byte(v)}
	case v <= 0xffffffff:
		return []byte{major | 26, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		return []byte{major | 27,
			byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

func cborBytes(b []byte) []byte {
	return append(cborHead(2, uint64(len(b))), b...)
}

func cborText(s string) []byte {
	return append(cborHead(3, uint64(len(s))), []byte(s)...)
}

func cborMapHeader(nPairs int) []byte {
	return cborHead(5, uint64(nPairs))
}

// cborKeyInt encodes a CBOR map key that may be a positive or negative
// integer (COSE_Key uses both, e.g. 1, 3, -1, -2, -3).
func cborKeyInt(k int64) []byte {
	if k < 0 {
		return cborNegInt(k)
	}
	return cborUint(uint64(k))
}

// coseKeyEC2 encodes a COSE_Key for an EC2 (P-256) public key: kty=EC2(2),
// alg=ES256(-7), crv=P-256(1), x, y.
// https://www.rfc-editor.org/rfc/rfc9053#section-7.1
func coseKeyEC2(x, y []byte) []byte {
	var buf []byte
	buf = append(buf, cborMapHeader(5)...)
	buf = append(buf, cborKeyInt(1)...)  // kty
	buf = append(buf, cborUint(2)...)    // EC2
	buf = append(buf, cborKeyInt(3)...)  // alg
	buf = append(buf, cborNegInt(-7)...) // ES256
	buf = append(buf, cborKeyInt(-1)...) // crv
	buf = append(buf, cborUint(1)...)    // P-256
	buf = append(buf, cborKeyInt(-2)...) // x
	buf = append(buf, cborBytes(x)...)
	buf = append(buf, cborKeyInt(-3)...) // y
	buf = append(buf, cborBytes(y)...)
	return buf
}

// attestationObjectNone encodes a WebAuthn AttestationObject with the
// "none" attestation format: {"fmt":"none","attStmt":{},"authData":<bytes>}.
func attestationObjectNone(authData []byte) []byte {
	var buf []byte
	buf = append(buf, cborMapHeader(3)...)
	buf = append(buf, cborText("fmt")...)
	buf = append(buf, cborText("none")...)
	buf = append(buf, cborText("attStmt")...)
	buf = append(buf, cborMapHeader(0)...)
	buf = append(buf, cborText("authData")...)
	buf = append(buf, cborBytes(authData)...)
	return buf
}
