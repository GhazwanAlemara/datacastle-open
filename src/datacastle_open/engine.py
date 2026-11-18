"""Deterministic local EU freight reconciliation, TARIC validation, EU AI Act classifier & tamper seal."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

DATACASTLE_OPEN_BASE = os.environ.get("DATACASTLE_API_URL", "https://datacastle.eu").rstrip("/")

TARIC_CHAPTER_GROUPS = [
    (1, 5, "Section I: Live Animals & Animal Products"),
    (6, 14, "Section II: Vegetable Products"),
    (15, 15, "Section III: Animal or Vegetable Fats & Oils"),
    (16, 24, "Section IV: Prepared Foodstuffs, Beverages & Tobacco"),
    (25, 27, "Section V: Mineral Products"),
    (28, 38, "Section VI: Chemical & Allied Industries"),
    (39, 40, "Section VII: Plastics & Rubber Articles"),
    (41, 43, "Section VIII: Hides, Skins & Leather"),
    (44, 46, "Section IX: Wood & Cork Articles"),
    (47, 49, "Section X: Pulp, Paper & Paperboard"),
    (50, 63, "Section XI: Textiles & Textile Articles"),
    (64, 67, "Section XII: Footwear & Headgear"),
    (68, 70, "Section XIII: Stone, Plaster, Cement & Glass"),
    (71, 71, "Section XIV: Precious Metals & Jewelry"),
    (72, 83, "Section XV: Base Metals & Articles"),
    (84, 85, "Section XVI: Machinery, Mechanical Appliances & Electrical Equipment"),
    (86, 89, "Section XVII: Vehicles, Aircraft & Vessels"),
    (90, 92, "Section XVIII: Optical, Medical & Precision Instruments"),
    (93, 93, "Section XIX: Arms & Ammunition"),
    (94, 96, "Section XX: Miscellaneous Manufactured Articles"),
    (97, 97, "Section XXI: Works of Art & Antiques"),
    (98, 99, "Section XXII: Complete Industrial Plant & Special CN Classifications"),
]

_PROHIBITED_MARKERS = (
    "social scoring",
    "subliminal manipulation",
    "emotion recognition workplace",
    "emotion recognition school",
    "untargeted facial scraping",
    "biometric categorization sensitive",
    "predictive policing profiling",
)

_HIGH_RISK_MARKERS = (
    "biometric",
    "critical infrastructure",
    "energy grid",
    "water supply",
    "recruitment",
    "cv screening",
    "hiring",
    "credit scoring",
    "loan eligibility",
    "insurance underwriting",
    "medical device",
    "triage",
    "law enforcement",
    "border control",
    "asylum",
    "judicial",
    "customs risk scoring",
    "safety component",
    "autonomous vehicle",
)

_TRANSPARENCY_MARKERS = (
    "chatbot",
    "customer support bot",
    "deepfake",
    "synthetic media",
    "ai-generated",
    "generative text",
    "voice synthesis",
)


def _norm_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def _digits_only(code: str) -> str:
    return re.sub(r"[^0-9]", "", code or "")


def validate_taric_code(tariff_code: str, goods_description: str = "") -> Dict[str, Any]:
    """Deterministically checks 6-digit HS, 8-digit EU CN, and 10-digit TARIC syntax and chapter."""
    raw = (tariff_code or "").strip()
    digits = _digits_only(raw)
    issues: List[str] = []

    if len(digits) not in (6, 8, 10):
        issues.append(
            f"Expected 6-digit HS, 8-digit EU CN, or 10-digit EU TARIC code; got {len(digits)} digits."
        )

    chapter = int(digits[:2]) if len(digits) >= 2 else 0
    if chapter < 1 or chapter > 99 or chapter == 77:
        issues.append(f"Chapter '{digits[:2]}' is invalid in the EU Combined Nomenclature (01-99, excluding 77).")

    section_name = "Unknown Chapter"
    for lo, hi, sec in TARIC_CHAPTER_GROUPS:
        if lo <= chapter <= hi:
            section_name = sec
            break

    formatted = digits
    if len(digits) == 10:
        formatted = f"{digits[:4]}.{digits[4:6]}.{digits[6:8]}.{digits[8:10]}"
    elif len(digits) == 8:
        formatted = f"{digits[:4]}.{digits[4:6]}.{digits[6:8]}"
    elif len(digits) == 6:
        formatted = f"{digits[:4]}.{digits[4:6]}"

    desc_clean = (goods_description or "").strip()
    if desc_clean and len(desc_clean) < 4:
        issues.append("Goods description is too vague for EU customs SAD Box 31 compliance.")

    if len(digits) == 6 and not issues:
        issues.append("HS-6 code lacks EU 8-digit CN / 10-digit TARIC subheading precision required for EU import declarations.")

    return {
        "valid": len([i for i in issues if "invalid" in i.lower() or "expected" in i.lower()]) == 0,
        "strict_eu_ready": len(issues) == 0 and len(digits) >= 8,
        "input_code": raw,
        "normalized_digits": digits,
        "formatted_taric": formatted,
        "code_precision": f"{len(digits)}-digit",
        "chapter": chapter,
        "section": section_name,
        "goods_description": desc_clean,
        "issues": issues,
    }


def reconcile_3way_freight(
    invoice_items: List[Dict[str, Any]],
    packing_items: List[Dict[str, Any]],
    currency: str = "EUR",
    weight_tolerance_pct: float = 2.0,
) -> Dict[str, Any]:
    """Deterministic 3-way reconciliation of Commercial Invoice lines against Packing List / CMR lines."""
    discrepancies: List[Dict[str, Any]] = []
    pack_by_sku: Dict[str, Dict[str, Any]] = {}
    pack_by_desc: Dict[str, Dict[str, Any]] = {}

    for p in packing_items:
        sku_k = _norm_key(str(p.get("sku") or ""))
        desc_k = _norm_key(str(p.get("description") or ""))
        if sku_k:
            pack_by_sku[sku_k] = p
        if desc_k:
            pack_by_desc[desc_k] = p

    matched_keys = set()
    total_invoice_value = 0.0
    total_invoice_weight = 0.0
    total_packing_weight = sum(float(p.get("weightKg") or p.get("grossWeightKg") or 0.0) for p in packing_items)

    for idx, inv in enumerate(invoice_items, start=1):
        desc = str(inv.get("description") or f"Line {idx}")
        sku_k = _norm_key(str(inv.get("sku") or ""))
        desc_k = _norm_key(desc)
        qty_inv = float(inv.get("quantity") or 0.0)
        unit_price = float(inv.get("unitPrice") or 0.0)
        total_val = float(inv.get("totalValue") or (qty_inv * unit_price))
        wt_inv = float(inv.get("weightKg") or inv.get("grossWeightKg") or 0.0)
        taric = str(inv.get("tariffCode") or inv.get("hsCode") or "").strip()

        total_invoice_value += total_val
        total_invoice_weight += wt_inv

        if unit_price > 0 and inv.get("totalValue") is not None:
            expected_val = round(qty_inv * unit_price, 2)
            if abs(expected_val - total_val) > 0.05:
                discrepancies.append({
                    "severity": "Critical",
                    "line": idx,
                    "item": desc,
                    "field": "totalValue",
                    "invoice_value": total_val,
                    "expected_value": expected_val,
                    "detail": f"Invoice line math variance ({currency} {total_val:.2f} vs qty*unit {expected_val:.2f}).",
                })

        if not taric:
            discrepancies.append({
                "severity": "Warning",
                "line": idx,
                "item": desc,
                "field": "tariffCode",
                "detail": "Missing EU CN/TARIC classification code on invoice line.",
            })
        else:
            taric_res = validate_taric_code(taric, desc)
            if not taric_res["strict_eu_ready"]:
                discrepancies.append({
                    "severity": "Critical" if not taric_res["valid"] else "Warning",
                    "line": idx,
                    "item": desc,
                    "field": "tariffCode",
                    "invoice_value": taric,
                    "detail": "; ".join(taric_res["issues"]),
                })

        pack = pack_by_sku.get(sku_k) if sku_k else None
        if pack is None:
            pack = pack_by_desc.get(desc_k)

        if pack is None:
            discrepancies.append({
                "severity": "Critical",
                "line": idx,
                "item": desc,
                "field": "linePresence",
                "detail": "Item on Commercial Invoice is missing from Packing List / CMR manifest.",
            })
            continue

        matched_keys.add(id(pack))
        qty_pack = float(pack.get("quantity") or 0.0)
        if abs(qty_inv - qty_pack) > 1e-6:
            discrepancies.append({
                "severity": "Critical",
                "line": idx,
                "item": desc,
                "field": "quantity",
                "invoice_value": qty_inv,
                "packing_value": qty_pack,
                "detail": f"Quantity mismatch: Invoice declares {qty_inv:g} units vs Packing/CMR {qty_pack:g} units.",
            })

        wt_pack = float(pack.get("weightKg") or pack.get("grossWeightKg") or 0.0)
        if wt_inv > 0 and wt_pack > 0:
            pct = abs(wt_inv - wt_pack) / max(wt_inv, wt_pack) * 100.0
            if pct > weight_tolerance_pct:
                discrepancies.append({
                    "severity": "Critical" if pct >= 5.0 else "Warning",
                    "line": idx,
                    "item": desc,
                    "field": "weightKg",
                    "invoice_value": wt_inv,
                    "packing_value": wt_pack,
                    "detail": f"Weight variance of {pct:.1f}% ({wt_inv:g} kg vs {wt_pack:g} kg) exceeds {weight_tolerance_pct:g}% customs tolerance.",
                })

        taric_pack = str(pack.get("tariffCode") or pack.get("hsCode") or "").strip()
        if taric and taric_pack and _digits_only(taric)[:8] != _digits_only(taric_pack)[:8]:
            discrepancies.append({
                "severity": "Critical",
                "line": idx,
                "item": desc,
                "field": "tariffCode",
                "invoice_value": taric,
                "packing_value": taric_pack,
                "detail": f"Tariff code mismatch between Invoice ({taric}) and CMR/Packing List ({taric_pack}).",
            })

    for p in packing_items:
        if id(p) not in matched_keys:
            discrepancies.append({
                "severity": "Critical",
                "line": None,
                "item": str(p.get("description") or p.get("sku") or "Unmatched Packing Item"),
                "field": "unbilledCargo",
                "detail": "Item exists on Packing List / CMR manifest but is missing from Commercial Invoice.",
            })

    critical_count = sum(1 for d in discrepancies if d["severity"] == "Critical")
    warning_count = sum(1 for d in discrepancies if d["severity"] == "Warning")
    status = "CLEAR" if not discrepancies else ("HOLD_REQUIRED" if critical_count > 0 else "REVIEW_WARNINGS")

    return {
        "status": status,
        "currency": currency.upper(),
        "invoice_lines": len(invoice_items),
        "packing_lines": len(packing_items),
        "total_invoice_value": round(total_invoice_value, 2),
        "total_invoice_weight_kg": round(total_invoice_weight, 2),
        "total_packing_weight_kg": round(total_packing_weight, 2),
        "critical_discrepancies": critical_count,
        "warnings": warning_count,
        "discrepancies": discrepancies,
    }


def classify_eu_ai_act(system_description: str, sector: str = "") -> Dict[str, Any]:
    """Deterministic EU AI Act (Regulation EU 2024/1689) risk tier & compliance obligations."""
    combined = f"{system_description or ''} {sector or ''}".lower()

    if any(m in combined for m in _PROHIBITED_MARKERS):
        tier = "PROHIBITED_ARTICLE_5"
        summary = "Matches Article 5 prohibited AI practices in the EU. Deployment is banned unless a statutory exemption applies."
        obligations = [
            "Immediately halt deployment in EU/EEA jurisdictions",
            "Document legal architecture redesign removing prohibited biometric/behavioral inference",
        ]
    elif any(m in combined for m in _HIGH_RISK_MARKERS):
        tier = "HIGH_RISK_ANNEX_III"
        summary = "Triggers Annex III / Safety Component High-Risk obligations under Articles 9-15 of Regulation (EU) 2024/1689."
        obligations = [
            "Art. 9: Continuous Risk Management System across lifecycle",
            "Art. 10: Data Governance & Bias Examination Logs",
            "Art. 11 & Annex IV: Technical Documentation Vault",
            "Art. 12: Automatic Tamper-Evident Event Logging",
            "Art. 14: Human Oversight & Intervention Controls",
            "Art. 43 & 49: Conformity Assessment & EU Database Registration",
        ]
    elif any(m in combined for m in _TRANSPARENCY_MARKERS):
        tier = "LIMITED_TRANSPARENCY_ART_50"
        summary = "Triggers Article 50 Transparency obligations requiring explicit AI interaction or synthetic-content labeling."
        obligations = [
            "Art. 50(1): Disclose AI interaction clearly to natural persons",
            "Art. 50(2): Machine-readable provenance marking for synthetic outputs",
        ]
    else:
        tier = "MINIMAL_RISK"
        summary = "No Annex III high-risk triggers detected; voluntary codes of conduct and GDPR baseline apply."
        obligations = [
            "Maintain GDPR Article 28 DPA & subprocessor inventory",
            "Keep voluntary model card and audit log for enterprise procurement",
        ]

    return {
        "regulation": "Regulation (EU) 2024/1689 (EU AI Act)",
        "risk_tier": tier,
        "summary": summary,
        "required_obligations": obligations,
    }


def canonical_json_bytes(payload: Any) -> bytes:
    """RFC 8785 deterministic canonical JSON encoding."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_tamper_evident_seal(
    payload: Dict[str, Any],
    api_key: Optional[str] = None,
    sync_cloud: bool = True,
) -> Dict[str, Any]:
    """Generates a deterministic SHA-256 verification seal and optionally registers it with DataCastle.eu."""
    issued_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    seal_id = f"dc_seal_{digest[:16]}"
    seal: Dict[str, Any] = {
        "seal_id": seal_id,
        "sha256": digest,
        "issued_at": issued_at,
        "engine": "datacastle-open/1.0.0",
        "attribution": "Verified by DataCastle.eu — Sovereign EU Customs & Compliance Engine",
        "verify_url": f"{DATACASTLE_OPEN_BASE}/open?verify={digest}",
        "cloud_synced": False,
    }

    key = (api_key or os.environ.get("DATACASTLE_API_KEY") or "").strip()
    if sync_cloud and key:
        try:
            body = json.dumps({"seal_id": seal_id, "sha256": digest, "summary": payload}).encode("utf-8")
            req = urllib.request.Request(
                f"{DATACASTLE_OPEN_BASE}/api/v1/open/verify-sync",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                    "User-Agent": "datacastle-open/1.0.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if 200 <= resp.status < 300:
                    cloud_data = json.loads(resp.read().decode("utf-8"))
                    seal["cloud_synced"] = True
                    seal["quota_remaining"] = cloud_data.get("quota_remaining")
        except (urllib.error.URLError, TimeoutError, ValueError):
            seal["cloud_synced"] = False

    return seal
