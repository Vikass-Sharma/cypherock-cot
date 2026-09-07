#!/usr/bin/env bash
set -e

# Base directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVER_BIN="$ROOT_DIR/build/server/cot_server"
CLIENT_ENTRY="$ROOT_DIR/client/dist/index.js"

if [ ! -f "$SERVER_BIN" ]; then
    echo "[Error] Server binary not found at $SERVER_BIN. Run cmake build first."
    exit 1
fi

if [ ! -f "$CLIENT_ENTRY" ]; then
    echo "[Error] Client dist entry not found at $CLIENT_ENTRY. Run npm run build in client first."
    exit 1
fi

SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}
trap cleanup EXIT INT TERM

echo "========================================================="
echo " Cypherock COT/MTA Stage 7: End-to-End TCP Test Suite"
echo "========================================================="

CASES=(
    "1:Random x, Random y"
    "2:x = 1, y = 1"
    "3:x = 5, y = 13"
    "4:x = p - 1, y = p - 1"
    "5:x = 0, y = 0"
    "6:x = 0, y = 42"
    "7:x = 42, y = 0"
)

BASE_PORT=9200
ALL_PASSED=true

for item in "${CASES[@]}"; do
    CASE_NUM="${item%%:*}"
    CASE_DESC="${item#*:}"
    PORT=$((BASE_PORT + CASE_NUM))

    echo ""
    echo "--- Running Scenario $CASE_NUM: $CASE_DESC (Port $PORT) ---"

    SERVER_LOG=$(mktemp)
    CLIENT_LOG=$(mktemp)

    # 1. Start Server in background
    "$SERVER_BIN" --port "$PORT" --case "$CASE_NUM" > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    # Short delay to allow server socket bind and listen
    sleep 0.2

    # 2. Run Client
    CLIENT_EXIT=0
    node "$CLIENT_ENTRY" --port "$PORT" --case "$CASE_NUM" > "$CLIENT_LOG" 2>&1 || CLIENT_EXIT=$?

    # 3. Wait for Server to exit cleanly
    SERVER_EXIT=0
    wait "$SERVER_PID" || SERVER_EXIT=$?
    SERVER_PID=""

    if [ "$CLIENT_EXIT" -ne 0 ]; then
        echo "  [FAIL] Client process exited with code $CLIENT_EXIT"
        cat "$CLIENT_LOG"
        ALL_PASSED=false
        break
    fi

    if [ "$SERVER_EXIT" -ne 0 ]; then
        echo "  [FAIL] Server process exited with code $SERVER_EXIT"
        cat "$SERVER_LOG"
        ALL_PASSED=false
        break
    fi

    # 4. Validate output assertions
    if ! grep -q "Verification: SUCCESS" "$SERVER_LOG"; then
        echo "  [FAIL] Server output does not indicate Verification: SUCCESS"
        cat "$SERVER_LOG"
        ALL_PASSED=false
        break
    fi

    if ! grep -q "Verification: SUCCESS" "$CLIENT_LOG"; then
        echo "  [FAIL] Client output does not indicate Verification: SUCCESS"
        cat "$CLIENT_LOG"
        ALL_PASSED=false
        break
    fi

    # Extract shares and products for display
    PRODUCT_LINE=$(grep "x\*y mod p" "$SERVER_LOG" | head -n 1)
    SUM_LINE=$(grep "(U+V) mod p" "$SERVER_LOG" | head -n 1)

    echo "  $PRODUCT_LINE"
    echo "  $SUM_LINE"
    echo "  Result: PASSED (Verification: SUCCESS)"

    rm -f "$SERVER_LOG" "$CLIENT_LOG"
done

echo ""
echo "========================================================="
if [ "$ALL_PASSED" = true ]; then
    echo " All 7 Stage 7 TCP End-to-End Scenarios: ALL PASSED"
else
    echo " Stage 7 TCP End-to-End Scenarios: FAILED"
    exit 1
fi
echo "========================================================="
