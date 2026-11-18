"""CLI & Self-Hosted Web Micro-UI entrypoint for datacastle-open."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from datacastle_open.engine import (
    DATACASTLE_OPEN_BASE,
    classify_eu_ai_act,
    generate_tamper_evident_seal,
    reconcile_3way_freight,
    validate_taric_code,
)

CONFIG_PATH = Path.home() / ".datacastle" / "config.json"

DEMO_INVOICE = [
    {"sku": "VLV-8481", "description": "Hydraulic Pressure Control Valve", "quantity": 120, "unitPrice": 145.0, "totalValue": 17400.0, "weightKg": 620.0, "tariffCode": "8481.80.59"},
    {"sku": "PMP-8413", "description": "Centrifugal Industrial Coolant Pump", "quantity": 40, "unitPrice": 380.0, "totalValue": 15200.0, "weightKg": 940.0, "tariffCode": "8413.70.51"},
]

DEMO_PACKING = [
    {"sku": "VLV-8481", "description": "Hydraulic Pressure Control Valve", "quantity": 120, "weightKg": 620.0, "tariffCode": "8481.20.90"},
    {"sku": "PMP-8413", "description": "Centrifugal Industrial Coolant Pump", "quantity": 36, "weightKg": 1120.0, "tariffCode": "8413.70.51"},
]

LOCAL_WEB_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>DataCastle Open | Self-Hosted EU Compliance &amp; Freight Vault</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0b1020; color: #f8fafc; margin: 0; padding: 24px; }
  .wrap { max-width: 960px; margin: 0 auto; }
  .card { background: #121a30; border: 1px solid #263252; border-radius: 12px; padding: 20px; margin-bottom: 18px; }
  h1 { margin: 0 0 8px; font-size: 24px; }
  textarea, input, button { font-family: inherit; border-radius: 8px; border: 1px solid #334155; padding: 10px 14px; }
  textarea, input { width: 100%; box-sizing: border-box; background: #090e1c; color: #e2e8f0; margin-top: 6px; }
  button { background: #facc15; color: #111827; font-weight: 700; cursor: pointer; margin-top: 12px; }
  pre { background: #050814; color: #4ade80; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
  .banner { background: #1e293b; border-left: 4px solid #facc15; padding: 12px 16px; border-radius: 8px; margin-bottom: 18px; font-size: 14px; }
  a { color: #facc15; }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>DataCastle Open — Local Sovereign Container</h1>
    <p>100% self-hosted EU 3-Way Freight Reconciliation, TARIC Check &amp; EU AI Act Classifier. Zero data leaves this server.</p>
  </div>
  <div class="banner">
    <strong>Need Cloud AI PDF extraction, Live EU TARIC Duty Rates &amp; Multi-User Team Approvals?</strong>
    Claim your Free Community Key (3 free cloud runs/mo) at <a href="https://datacastle.eu/open" target="_blank" rel="noreferrer">datacastle.eu/open</a>.
  </div>
  <div class="card">
    <h3>Run Local 3-Way Freight Reconciliation</h3>
    <label>Invoice Items JSON</label>
    <textarea id="inv" rows="4">[{"sku":"VLV-8481","description":"Hydraulic Valve","quantity":120,"unitPrice":145,"totalValue":17400,"weightKg":620,"tariffCode":"8481.80.59"}]</textarea>
    <label>Packing List / CMR Items JSON</label>
    <textarea id="pack" rows="4">[{"sku":"VLV-8481","description":"Hydraulic Valve","quantity":116,"weightKg":695,"tariffCode":"8481.20.90"}]</textarea>
    <button onclick="runCheck()">Verify Locally &amp; Generate Seal</button>
    <pre id="out">Ready.</pre>
  </div>
</div>
<script>
async function runCheck() {
  const out = document.getElementById('out');
  try {
    const res = await fetch('/api/reconcile', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        invoice_items: JSON.parse(document.getElementById('inv').value),
        packing_items: JSON.parse(document.getElementById('pack').value)
      })
    });
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}
</script>
</body>
</html>
"""


def _load_saved_api_key() -> str:
    env_key = (os.environ.get("DATACASTLE_API_KEY") or "").strip()
    if env_key:
        return env_key
    if CONFIG_PATH.exists():
        try:
            return str(json.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("api_key") or "").strip()
        except Exception:
            return ""
    return ""


def _print_footer(api_key: str) -> None:
    if not api_key:
        print(
            "\n[Connected Open-Source] Claim your Free Community API Key "
            "(3 free Cloud AI PDF extractions & live TARIC duty syncs/mo) at: "
            f"{DATACASTLE_OPEN_BASE}/open",
            file=sys.stderr,
        )


def _serve_local(port: int) -> int:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send(200, b'{"status":"ok","engine":"datacastle-open"}', "application/json")
                return
            self._send(200, LOCAL_WEB_HTML.encode("utf-8"), "text/html; charset=utf-8")

        def do_POST(self) -> None:
            try:
                raw_len = self.headers.get("Content-Length", "0")
                length = int(raw_len)
                if length < 0 or length > 1_048_576:
                    self._send(413, b'{"error":"Request payload must be 0 to 1MB"}', "application/json")
                    return
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if not isinstance(payload, dict):
                    self._send(400, b'{"error":"JSON object payload required"}', "application/json")
                    return
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json")
                return

            try:
                if self.path == "/api/reconcile":
                    inv = payload.get("invoice_items", [])
                    pack = payload.get("packing_items", [])
                    if not isinstance(inv, list) or not isinstance(pack, list):
                        self._send(400, b'{"error":"invoice_items and packing_items must be JSON arrays"}', "application/json")
                        return
                    result = reconcile_3way_freight(
                        inv[:100],
                        pack[:100],
                        currency=str(payload.get("currency") or "EUR"),
                    )
                elif self.path == "/api/taric":
                    result = validate_taric_code(
                        str(payload.get("tariff_code") or ""),
                        str(payload.get("goods_description") or ""),
                    )
                elif self.path == "/api/ai-act":
                    result = classify_eu_ai_act(
                        str(payload.get("system_description") or ""),
                        str(payload.get("sector") or ""),
                    )
                else:
                    self._send(404, b'{"error":"Not found"}', "application/json")
                    return
            except (TypeError, ValueError) as exc:
                self._send(400, json.dumps({"error": f"Invalid field value: {exc}"}).encode("utf-8"), "application/json")
                return

            seal = generate_tamper_evident_seal(result, api_key=_load_saved_api_key(), sync_cloud=False)
            out = json.dumps({"result": result, "seal": seal}, indent=2).encode("utf-8")
            self._send(200, out, "application/json")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"[datacastle-open] Self-hosted UI & API running on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="datacastle-open", description="DataCastle Open EU Customs & Compliance CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("reconcile", help="3-way Commercial Invoice vs Packing List / CMR check")
    p_rec.add_argument("--invoice", help="Path to invoice line-items JSON")
    p_rec.add_argument("--packing", help="Path to packing/CMR line-items JSON")
    p_rec.add_argument("--currency", default="EUR")
    p_rec.add_argument("--demo", action="store_true", help="Run built-in Nordic shipment discrepancy demo")

    p_taric = sub.add_parser("taric", help="Validate 8-digit CN or 10-digit EU TARIC code")
    p_taric.add_argument("code")
    p_taric.add_argument("--desc", default="")

    p_ai = sub.add_parser("ai-act", help="Classify system under Regulation (EU) 2024/1689 (EU AI Act)")
    p_ai.add_argument("--system", required=True)
    p_ai.add_argument("--sector", default="")

    p_act = sub.add_parser("activate", help="Store and verify your Free Community API Key")
    p_act.add_argument("api_key")

    p_srv = sub.add_parser("serve", help="Run self-hosted local web UI and JSON API")
    p_srv.add_argument("--port", type=int, default=8090)

    args = parser.parse_args(argv)
    api_key = _load_saved_api_key()

    if args.cmd == "reconcile":
        if args.demo or (not args.invoice and not args.packing):
            inv, pack = DEMO_INVOICE, DEMO_PACKING
        else:
            inv = json.loads(Path(args.invoice).read_text(encoding="utf-8"))
            pack = json.loads(Path(args.packing).read_text(encoding="utf-8"))
        res = reconcile_3way_freight(inv, pack, currency=args.currency)
        seal = generate_tamper_evident_seal(res, api_key=api_key)
        print(json.dumps({"result": res, "seal": seal}, indent=2))
        _print_footer(api_key)
        return 0

    if args.cmd == "taric":
        res = validate_taric_code(args.code, args.desc)
        seal = generate_tamper_evident_seal(res, api_key=api_key)
        print(json.dumps({"result": res, "seal": seal}, indent=2))
        _print_footer(api_key)
        return 0

    if args.cmd == "ai-act":
        res = classify_eu_ai_act(args.system, args.sector)
        seal = generate_tamper_evident_seal(res, api_key=api_key)
        print(json.dumps({"result": res, "seal": seal}, indent=2))
        _print_footer(api_key)
        return 0

    if args.cmd == "activate":
        key = args.api_key.strip()
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps({"api_key": key}, indent=2), encoding="utf-8")
        try:
            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            pass
        try:
            req = urllib.request.Request(
                f"{DATACASTLE_OPEN_BASE}/api/v1/open/status",
                headers={"Authorization": f"Bearer {key}", "User-Agent": "datacastle-open/1.0.0"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status_data = json.loads(resp.read().decode("utf-8"))
                print(json.dumps({"activated": True, "remote_status": status_data}, indent=2))
                return 0
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            print(json.dumps({"activated_locally": True, "warning": f"Saved locally; remote check skipped ({exc})"}, indent=2))
            return 0

    if args.cmd == "serve":
        return _serve_local(args.port)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
