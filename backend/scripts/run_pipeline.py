#!/usr/bin/env python3
"""
End-to-End Compliance Pipeline Runner
=====================================
Executes the full continuous compliance pipeline:
1. Ingestion / Collection from connected GitHub repositories
2. Normalization into canonical CCDM records
3. Correlation of change-to-code, reviews, and deployments
4. Evidence harvesting and SHA-256 integrity verification
5. Policy Evaluation across all 15 Change Management Controls (CM-001 - CM-015)
6. Summary reporting of Compliant vs Pending Controls
"""

import sys
import os
import argparse
from datetime import datetime, UTC

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.postgres import SessionLocal
from app.models.orm import ConnectorAccountORM, ChangeORM, FindingORM, CheckResultORM, EvidenceMetadataORM
from app.services.collection_service import CollectionService
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.change_control_orchestrator import ChangeControlOrchestrator
from app.api.routes.compliance import run_full_sync_and_evaluation

def run_pipeline(tenant_id: str = "tenant-acme-corp", account_id: str = None, repo_name: str = None):
    print("=" * 70)
    print("🚀 STARTING AUTOMATED CONTINUOUS COMPLIANCE PIPELINE")
    print("=" * 70)
    print(f"Timestamp: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Tenant ID: {tenant_id}")
    
    db = SessionLocal()
    try:
        # Find active connector account
        if not account_id:
            acc = db.query(ConnectorAccountORM).filter_by(tenant_id=tenant_id).first()
            if not acc:
                print("❌ No active connector accounts found for this tenant.")
                return
            account_id = acc.account_id
            
        print(f"Connected Account: {account_id}")
        
        # 1. Run full sync and evaluation
        print("\n[Step 1/5] Ingesting Live Data from GitHub...")
        print("[Step 2/5] Normalizing into Canonical CCDM Entities...")
        print("[Step 3/5] Correlating Changes, Reviews & Deployments...")
        print("[Step 4/5] Harvesting Cryptographic SHA-256 Evidence...")
        print("[Step 5/5] Evaluating Change Controls (CM-001 - CM-015)...")
        
        run_full_sync_and_evaluation(tenant_id=tenant_id, account_id=account_id, repository=repo_name)
        
        # 2. Report summary
        changes = db.query(ChangeORM).filter_by(tenant_id=tenant_id).all()
        findings = db.query(FindingORM).filter_by(tenant_id=tenant_id, status="OPEN").all()
        evidence_count = db.query(EvidenceMetadataORM).filter_by(tenant_id=tenant_id).count()
        
        failing_check_ids = set(f.check_id for f in findings)
        total_checks = 15
        compliant_checks = total_checks - len(failing_check_ids)
        
        print("\n" + "=" * 70)
        print("📊 PIPELINE EXECUTION SUMMARY & AUDIT RESULTS")
        print("=" * 70)
        print(f"✔ Total Changes Ingested:   {len(changes)}")
        print(f"✔ Evidence Records Stored:  {evidence_count} (SHA-256 Verified)")
        print(f"✔ Controls Evaluated:       {total_checks}/15")
        print(f"✔ Compliant Controls:       {compliant_checks} (PASS)")
        print(f"⚠ Pending Remediations:     {len(failing_check_ids)} (FAIL: {', '.join(sorted(failing_check_ids)) if failing_check_ids else 'None'})")
        print("=" * 70)
        print("✅ Pipeline execution completed successfully. Frontend updated via real-time SSE.\n")
        
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run full continuous compliance pipeline")
    parser.add_argument("--tenant-id", default="tenant-acme-corp", help="Tenant ID")
    parser.add_argument("--account-id", default=None, help="Connector Account ID")
    parser.add_argument("--repo", default=None, help="Specific repository to sync (e.g. Vetri1706/support-ticket-classifier)")
    args = parser.parse_args()
    
    run_pipeline(tenant_id=args.tenant_id, account_id=args.account_id, repo_name=args.repo)
