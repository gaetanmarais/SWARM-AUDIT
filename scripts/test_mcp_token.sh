#!/bin/bash
# Test MCP account token against Anthropic API with both header formats

DB="/opt/claude-hub/app/backend/data/claudehub.db"
TOKEN=$(sqlite3 "$DB" "SELECT access_token FROM claude_accounts WHERE role='mcp';")

if [ -z "$TOKEN" ]; then
    echo "ERROR: no access_token found for role=mcp"
    exit 1
fi

echo "Token prefix: ${TOKEN:0:20}..."
echo ""

echo "=== Test 1: claude-haiku-4-5-20251001 ==="
curl -s -X POST https://api.anthropic.com/v1/messages \
    -H "Authorization: Bearer $TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d '{"model":"claude-haiku-4-5-20251001","max_tokens":50,"messages":[{"role":"user","content":"Reply with just: OK"}]}' \
    | python3 -m json.tool 2>/dev/null || echo "(invalid JSON)"

echo ""
echo "=== Test 2: claude-sonnet-4-6 ==="
curl -s -X POST https://api.anthropic.com/v1/messages \
    -H "Authorization: Bearer $TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d '{"model":"claude-sonnet-4-6","max_tokens":50,"messages":[{"role":"user","content":"Reply with just: OK"}]}' \
    | python3 -m json.tool 2>/dev/null || echo "(invalid JSON)"
