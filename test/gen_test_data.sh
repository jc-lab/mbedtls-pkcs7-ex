#!/bin/bash
set -e
OUTDIR="test_cases"
mkdir -p "$OUTDIR"

# 1️⃣ payload 준비
echo "Hello PKCS7 attached content!" > "$OUTDIR/payload.txt"

# 2️⃣ CA 키/인증서 생성 (ECDSA)
openssl ecparam -name prime256v1 -genkey -noout -out "$OUTDIR/ca.key"
openssl req -x509 -new -key "$OUTDIR/ca.key" -days 3650 \
  -subj "/CN=Test ECDSA CA" -out "$OUTDIR/ca.crt"

# 3️⃣ 서명자 키/CSR/인증서 생성 (ECDSA)
openssl ecparam -name prime256v1 -genkey -noout -out "$OUTDIR/signer.key"
openssl req -new -key "$OUTDIR/signer.key" \
  -subj "/CN=Test ECDSA Signer" -out "$OUTDIR/signer.csr"

openssl x509 -req -in "$OUTDIR/signer.csr" \
  -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
  -days 365 -out "$OUTDIR/signer.crt"

# 4️⃣ PKCS#7 생성
# (A) attached (signedAttrs 포함)
openssl smime -sign -nodetach -binary -in "$OUTDIR/payload.txt" \
  -signer "$OUTDIR/signer.crt" -inkey "$OUTDIR/signer.key" \
  -certfile "$OUTDIR/ca.crt" -outform DER \
  -out "$OUTDIR/case1_attached.der"

cat > "$OUTDIR/case1_attached.txt" <<EOF
# Test Case 1 (ECDSA)
description: Attached content (ECDSA, signedAttrs)
expect_verify: OK
expect_length: $(wc -c < "$OUTDIR/payload.txt")
payload_sha256: $(openssl dgst -sha256 -binary "$OUTDIR/payload.txt" | xxd -p -c 256)
EOF

# (B) attached (signedAttrs 없음)
openssl smime -sign -nodetach -binary -in "$OUTDIR/payload.txt" \
  -signer "$OUTDIR/signer.crt" -inkey "$OUTDIR/signer.key" \
  -certfile "$OUTDIR/ca.crt" -noattr -outform DER \
  -out "$OUTDIR/case2_noattrs.der"

cat > "$OUTDIR/case2_noattrs.txt" <<EOF
# Test Case 2 (ECDSA)
description: Attached content (ECDSA, no signedAttrs)
expect_verify: OK
expect_length: $(wc -c < "$OUTDIR/payload.txt")
payload_sha256: $(openssl dgst -sha256 -binary "$OUTDIR/payload.txt" | xxd -p -c 256)
EOF

echo "✅ ECDSA P-256 PKCS#7 test data generated under $OUTDIR/"
