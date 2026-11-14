# Assert helpers for in-VM scenarios (source this file).
assert_contains() {
    grep -qF -- "$2" "$1" || { echo "ASSERT FAIL: '$2' not in $1"; cat "$1"; exit 1; }
}
