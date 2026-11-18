# DataCastle Open — Self-Hosted EU Customs, Freight & EU AI Act Engine

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![EU Data Sovereignty](https://img.shields.io/badge/EU_Sovereign-Zero_Data_Leaves-green.svg)](https://datacastle.eu/open)

**Stop paying legacy logistics suites thousands per seat just to catch customs holds before border filing.**

`datacastle-open` is the open-source, self-hostable local engine from [DataCastle.eu](https://datacastle.eu/open). It runs 100% locally in Docker or Python so your confidential supplier invoices, freight rates, and customs declarations never leave your network.

```
Commercial Invoice ──┐
Packing List       ──┼──▶ datacastle-open (Local) ──▶ SHA-256 Tamper Seal
CMR Waybill        ──┘          │
                                ▼ (Optional Free Community Key)
                         DataCastle.eu EU Cloud (AI PDF OCR + Live TARIC Duty)
```

---

## 30-Second Quickstart

### Option 1: Docker Compose (Self-Hosted Web UI + API)
```bash
git clone https://github.com/GhazwanAlemara/datacastle-open.git
cd datacastle-open
docker compose up -d
# Open http://localhost:8090
```

### Option 2: Python CLI
```bash
pip install datacastle-open
# Run the built-in Nordic freight discrepancy check immediately:
datacastle-open reconcile --demo

# Validate an EU TARIC / CN customs code:
datacastle-open taric 8481.80.59 --desc "Hydraulic pressure valve"

# Classify a system under the EU AI Act (Regulation EU 2024/1689):
datacastle-open ai-act --system "Automated CV screening for candidate ranking"
```

---

## Free Self-Hosted vs. DataCastle EU Sovereign Cloud

| Capability | `datacastle-open` (Apache-2.0) | Community Free Key (`dc_free_`) | DataCastle Pro / Partner (`datacastle.eu`) |
| :--- | :--- | :--- | :--- |
| 3-Way Freight Reconciliation (JSON) | **Unlimited ($0)** | **Unlimited** | **Unlimited + Multi-User Approval** |
| TARIC / CN Code Syntax Check | **Unlimited ($0)** | **Unlimited** | **Live EU Duty & Sanctions Sync** |
| EU AI Act Risk Classifier | **Unlimited ($0)** | **Unlimited** | **Audit-Ready Annex IV Vault** |
| SHA-256 Tamper-Evident Seals | **Local Offline** | **Cloud Registry Sync** | **Signed PDF Certificates** |
| Cloud AI OCR for Messy PDF Scans | — | **3 Free / Month** | **Automated Inbox Ingestion** |
| White-Label Client Portal | — | — | **Included (Partner Tier)** |

### Claim Your Free Community API Key
Unlock **3 free Cloud AI PDF extractions & live EU TARIC lookups per month** with one click at **[https://datacastle.eu/open](https://datacastle.eu/open)**, then activate locally:

```bash
datacastle-open activate dc_free_your_key_here
```

No Docker? Test the exact same engine right in your browser with zero login at **[https://datacastle.eu/open](https://datacastle.eu/open)**.
