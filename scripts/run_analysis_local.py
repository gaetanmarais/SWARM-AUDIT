#!/usr/bin/env python3
# Version: 1.0.0
# Date:    2026-06-20
# Notes:   Run analysis locally from JSON dumps — bypasses VM/Docker

"""
Usage:
  python3 scripts/run_analysis_local.py --dumps dumps/dumps/ [options]

Options:
  --dumps     DIR   Path to directory containing *.json audit dumps
  --mcp-url   URL   Hub MCP URL (or set CLAUDE_HUB_MCP_URL env)
  --mcp-token TOK   Hub MCP token (or set CLAUDE_HUB_MCP_TOKEN env)
  --api-key   KEY   Anthropic API key for direct mode (or set ANTHROPIC_API_KEY env)
  --out       FILE  Write AnalysisResult JSON to file (default: analysis_result.json)
"""

import asyncio
import json
import os
import sys
import argparse
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from models import AuditResult, AnalysisResult
from analysis import run_analysis


def load_dumps(dumps_dir: str) -> list[AuditResult]:
    results = []
    for p in sorted(Path(dumps_dir).glob("*.json")):
        try:
            data = json.loads(p.read_text())
            results.append(AuditResult(**data))
            print(f"  loaded: {p.name} → roles: {[r['role'] for r in data.get('roles', [])]}")
        except Exception as e:
            print(f"  SKIP {p.name}: {e}", file=sys.stderr)
    return results


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dumps", default="dumps/dumps/")
    parser.add_argument("--mcp-url", default=os.environ.get("CLAUDE_HUB_MCP_URL", "https://claude-ws-gmarais.duckdns.org/mcp"))
    parser.add_argument("--mcp-token", default=os.environ.get("CLAUDE_HUB_MCP_TOKEN", ""))
    parser.add_argument("--api-key", default=os.environ.get("ANTHROPIC_API_KEY", ""))
    parser.add_argument("--out", default="analysis_result.json")
    args = parser.parse_args()

    print(f"Loading dumps from {args.dumps}…")
    results = load_dumps(args.dumps)
    print(f"  → {len(results)} servers loaded\n")

    if not results:
        print("No dumps found, aborting.", file=sys.stderr)
        sys.exit(1)

    backend = "auto"
    if args.api_key:
        print(f"Mode: direct Anthropic API (key: {args.api_key[:8]}…)")
        backend = "direct"
    elif args.mcp_token:
        print(f"Mode: Hub MCP ask_claude ({args.mcp_url})")
        backend = "hub_mcp"
    else:
        print("ERROR: provide --api-key or --mcp-token", file=sys.stderr)
        sys.exit(1)

    cancel_flag = [False]

    def on_progress(msg: str):
        print(f"  [{msg}]")

    print("\nStarting analysis…")
    result: AnalysisResult = await run_analysis(
        results=results,
        mcp_url=args.mcp_url,
        mcp_token=args.mcp_token,
        cancel_flag=cancel_flag,
        anthropic_api_key=args.api_key,
        analysis_backend=backend,
        on_progress=on_progress,
    )

    out_path = args.out
    Path(out_path).write_text(result.model_dump_json(indent=2))
    print(f"\nDone → {out_path}")

    # Quick summary
    for mod in result.modules:
        criticals = [f for f in mod.config_findings if f.severity == "CRITICAL"]
        warnings  = [f for f in mod.config_findings if f.severity == "WARNING"]
        print(f"  {mod.role:20s}  CRIT:{len(criticals)}  WARN:{len(warnings)}  — {mod.summary[:80]}")


if __name__ == "__main__":
    asyncio.run(main())
