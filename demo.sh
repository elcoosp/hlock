#!/usr/bin/env bash
set -uo pipefail

echo "=== hlock v0.16.0 Demo Script ==="
echo ""

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
DEMO_DIR="/tmp/hlock-demo"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "Step 1: Build hlock"
cd "$REPO_ROOT"
cargo build --release 2>&1 | tail -1
echo ""

HLOCK="$REPO_ROOT/target/release/hlock"

echo "Step 2: Generate demo lockfile"
cargo run --example generate_demo > "$DEMO_DIR/demo.hlock" 2>/dev/null
echo "  Written to $DEMO_DIR/demo.hlock"
head -5 "$DEMO_DIR/demo.hlock"
echo "  ..."
echo ""

echo "Step 3: Verify digest"
"$HLOCK" verify "$DEMO_DIR/demo.hlock"
echo ""

echo "Step 4: Verify with trusted key (Ed25519)"
SEED_HEX="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SIGNING_KEY=$(cd "$REPO_ROOT" && cargo run --example generate_demo 2>/dev/null | head -1 | true)
PUBKEY=$(
  python3 -c "
import hashlib, base64, struct
seed = bytes.fromhex('$SEED_HEX')
# Ed25519 public key derivation - we just read it from the lockfile
import subprocess
result = subprocess.run(['grep', '@trust-root', '$DEMO_DIR/demo.hlock'], capture_output=True, text=True)
parts = result.stdout.strip().split()
print(parts[3] if len(parts) > 3 else '')
" 2>/dev/null
)
if [ -n "$PUBKEY" ]; then
  "$HLOCK" verify "$DEMO_DIR/demo.hlock" --trusted-key "ci@company.com:ed25519:$PUBKEY"
else
  echo "  (Skipped - could not extract pubkey)"
fi
echo ""

echo "Step 5: Lint (text format)"
"$HLOCK" lint "$DEMO_DIR/demo.hlock"
LINT_EXIT=$?
echo "  Exit code: $LINT_EXIT"
echo ""

echo "Step 6: Lint (JSON format)"
"$HLOCK" lint "$DEMO_DIR/demo.hlock" --format json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20
echo ""

echo "Step 7: Audit (text format)"
"$HLOCK" audit "$DEMO_DIR/demo.hlock"
AUDIT_EXIT=$?
echo "  Exit code: $AUDIT_EXIT"
echo ""

echo "Step 8: Audit (JSON format)"
"$HLOCK" audit "$DEMO_DIR/demo.hlock" --format json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20
echo ""

echo "Step 9: Diff - create a modified lockfile"
cargo run --example generate_demo 2>/dev/null | sed 's/express/express-new/g' > "$DEMO_DIR/demo2.hlock"
"$HLOCK" diff "$DEMO_DIR/demo.hlock" "$DEMO_DIR/demo2.hlock"
echo ""

echo "Step 10: Diff (JSON format)"
"$HLOCK" diff "$DEMO_DIR/demo.hlock" "$DEMO_DIR/demo2.hlock" --format json 2>/dev/null | python3 -m json.tool 2>/dev/null
echo ""

echo "Step 11: Generate SBOM (SPDX)"
"$HLOCK" sbom "$DEMO_DIR/demo.hlock" --namespace "my-app-ns" --format spdx-json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30
echo ""

echo "Step 12: Generate SBOM (CycloneDX)"
"$HLOCK" sbom "$DEMO_DIR/demo.hlock" --namespace "my-app-ns" --format cyclonedx-json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30
echo ""

echo "Step 13: Extract subgraph (my-app only)"
"$HLOCK" graph "$DEMO_DIR/demo.hlock" --root my-app > "$DEMO_DIR/subgraph.hlock"
echo "  Subgraph written to $DEMO_DIR/subgraph.hlock"
head -5 "$DEMO_DIR/subgraph.hlock"
echo ""

echo "Step 14: Extract subgraph with platform filter"
"$HLOCK" graph "$DEMO_DIR/demo.hlock" --root my-app --platform linux-x86_64 > "$DEMO_DIR/subgraph_linux.hlock" 2>&1
echo ""

echo "Step 15: Merge test"
cp "$DEMO_DIR/demo.hlock" "$DEMO_DIR/base.hlock"
cp "$DEMO_DIR/demo.hlock" "$DEMO_DIR/ours.hlock"
cp "$DEMO_DIR/demo2.hlock" "$DEMO_DIR/theirs.hlock"
"$HLOCK" merge --base "$DEMO_DIR/base.hlock" --ours "$DEMO_DIR/ours.hlock" --theirs "$DEMO_DIR/theirs.hlock" --strategy ours > "$DEMO_DIR/merged.hlock" 2>&1
MERGE_EXIT=$?
echo "  Merge exit code: $MERGE_EXIT"
echo ""

echo "Step 16: Sign the lockfile (Ed25519)"
SEED_HEX="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
"$HLOCK" sign "$DEMO_DIR/demo.hlock" --key-id "ci@company.com" --algorithm ed25519 --private-key "$SEED_HEX" --expires 1800000000 > "$DEMO_DIR/signed.hlock"
SIGN_EXIT=$?
echo "  Sign exit code: $SIGN_EXIT"
if [ $SIGN_EXIT -eq 0 ]; then
  echo "  Verifying signed lockfile..."
  "$HLOCK" verify "$DEMO_DIR/signed.hlock" --trusted-key "ci@company.com:ed25519:$PUBKEY"
fi
echo ""

echo "=== Demo Complete ==="
echo "Demo files are in $DEMO_DIR/"
ls -la "$DEMO_DIR/"
