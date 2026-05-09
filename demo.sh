#!/usr/bin/env bash
set -uo pipefail

echo "=== hlock v0.17.0 Demo Script ==="
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

echo "Step 2: Generate demo lockfiles (v1 and v2)"
cargo run --example generate_demo 2>/dev/null > "$DEMO_DIR/demo.hlock"
cargo run --example generate_demo v2 2>/dev/null > "$DEMO_DIR/demo_v2.hlock"
echo "  v1: $DEMO_DIR/demo.hlock (6 packages, lodash 4.17.21)"
echo "  v2: $DEMO_DIR/demo_v2.hlock (7 packages, lodash 4.17.22, added axios)"
head -5 "$DEMO_DIR/demo.hlock"
echo "  ..."
echo ""

echo "Step 3: Verify digest"
"$HLOCK" verify "$DEMO_DIR/demo.hlock"
echo ""

echo "Step 4: Lint (text)"
"$HLOCK" lint "$DEMO_DIR/demo.hlock"
LINT_EXIT=$?
echo "  Exit code: $LINT_EXIT"
echo ""

echo "Step 5: Lint (JSON)"
"$HLOCK" lint "$DEMO_DIR/demo.hlock" --format json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -15
echo "  ..."
echo ""

echo "Step 6: Audit (text)"
"$HLOCK" audit "$DEMO_DIR/demo.hlock"
AUDIT_EXIT=$?
echo "  Exit code: $AUDIT_EXIT"
echo ""

echo "Step 7: Audit (JSON)"
"$HLOCK" audit "$DEMO_DIR/demo.hlock" --format json 2>/dev/null | python3 -m json.tool 2>/dev/null
echo ""

echo "Step 8: Diff v1 vs v2"
"$HLOCK" diff "$DEMO_DIR/demo.hlock" "$DEMO_DIR/demo_v2.hlock"
echo ""

echo "Step 9: Diff v1 vs v2 (JSON)"
"$HLOCK" diff "$DEMO_DIR/demo.hlock" "$DEMO_DIR/demo_v2.hlock" --format json 2>/dev/null | python3 -m json.tool 2>/dev/null
echo ""

echo "Step 10: SBOM (SPDX)"
"$HLOCK" sbom "$DEMO_DIR/demo.hlock" --namespace "my-app-ns" --format spdx-json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20
echo "  ..."
echo ""

echo "Step 11: SBOM (CycloneDX)"
"$HLOCK" sbom "$DEMO_DIR/demo.hlock" --namespace "my-app-ns" --format cyclonedx-json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -15
echo "  ..."
echo ""

echo "Step 12: Extract subgraph (my-app)"
"$HLOCK" graph "$DEMO_DIR/demo.hlock" --root my-app > "$DEMO_DIR/subgraph.hlock"
echo "  Subgraph packages:"
grep -v '^@' "$DEMO_DIR/subgraph.hlock" | grep -v '^$' | cut -f1
echo ""

echo "Step 13: Sign + Verify (Ed25519)"
SEED_HEX="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUBKEY=$(grep '@trust-root' "$DEMO_DIR/demo.hlock" | awk '{print $4}')
"$HLOCK" sign "$DEMO_DIR/demo.hlock" --key-id "ci@company.com" --algorithm ed25519 --private-key "$SEED_HEX" --expires 1800000000 > "$DEMO_DIR/signed.hlock" 2>/dev/null
echo "  Signed lockfile created"
"$HLOCK" verify "$DEMO_DIR/signed.hlock" --trusted-key "ci@company.com:ed25519:$PUBKEY"
echo ""

echo "Step 14: Merge (base=v1, ours=v1, theirs=v2, strategy=ours)"
"$HLOCK" merge --base "$DEMO_DIR/demo.hlock" --ours "$DEMO_DIR/demo.hlock" --theirs "$DEMO_DIR/demo_v2.hlock" --strategy ours > "$DEMO_DIR/merged.hlock" 2>&1
MERGE_EXIT=$?
echo "  Merge exit code: $MERGE_EXIT"
echo ""

echo "Step 15: Info command"
"$HLOCK" info "$DEMO_DIR/demo.hlock"
echo ""

echo "Step 16: Why command (why is lodash in the lockfile?)"
"$HLOCK" why "$DEMO_DIR/demo.hlock" lodash
echo ""

echo "Step 17: Deps command (direct deps of my-app)"
"$HLOCK" deps "$DEMO_DIR/demo.hlock" my-app
echo ""

echo "Step 18: Deps command (transitive deps of my-app)"
"$HLOCK" deps "$DEMO_DIR/demo.hlock" my-app --transitive
echo ""

echo "Step 19: Dependents command (who depends on lodash?)"
"$HLOCK" dependents "$DEMO_DIR/demo.hlock" lodash
echo ""

echo "Step 20: Dependents command (transitive dependents of lodash)"
"$HLOCK" dependents "$DEMO_DIR/demo.hlock" lodash --transitive
echo ""

echo "Step 21: Tree command"
"$HLOCK" tree "$DEMO_DIR/demo.hlock"
echo ""

echo "Step 22: Tree command (--root my-app)"
"$HLOCK" tree "$DEMO_DIR/demo.hlock" --root my-app
echo ""

echo "Step 23: Dedup command"
"$HLOCK" dedup "$DEMO_DIR/demo.hlock"
echo ""

echo "Step 24: Licenses command"
"$HLOCK" licenses "$DEMO_DIR/demo.hlock"
echo ""

echo "Step 25: Licenses command (--missing)"
"$HLOCK" licenses "$DEMO_DIR/demo.hlock" --missing
echo ""

echo "Step 26: Check command"
"$HLOCK" check "$DEMO_DIR/demo.hlock"
CHECK_EXIT=$?
echo "  Exit code: $CHECK_EXIT"
echo ""

echo "Step 27: Completions (bash)"
"$HLOCK" completions bash | head -5
echo "  ..."
echo ""

echo "=== Demo Complete ==="
echo "Files in $DEMO_DIR/:"
ls -la "$DEMO_DIR/"
