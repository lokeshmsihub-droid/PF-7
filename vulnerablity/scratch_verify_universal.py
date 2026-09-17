import time
import requests
import json

BASE_URL = "http://localhost:8000"

def main():
    print("=== 1. Check Engine Cluster Readiness ===")
    r = requests.get(f"{BASE_URL}/repositories/engines/readiness")
    assert r.status_code == 200, f"Readiness endpoint failed: {r.text}"
    engines = r.json()
    print("Engines:", json.dumps(engines, indent=2))
    assert len(engines) >= 4

    print("\n=== 2. Validate Remote / Local Repository ===")
    val_payload = {
        "repository_url": "/Users/lokesh/Documents/semgrep repo/demo_vulnerable_repo",
        "branch": "main"
    }
    r = requests.post(f"{BASE_URL}/repositories/validate", json=val_payload)
    assert r.status_code == 200, f"Validation failed: {r.text}"
    val_res = r.json()
    print("Validation Result:", json.dumps(val_res, indent=2))
    assert val_res["valid"] is True
    assert val_res["access_status"] == "accessible"

    print("\n=== 3. Enqueue Real Multi-Scanner Celery Job ===")
    scan_payload = {
        "repository_id": "demo-universal-001",
        "repository_name": "/Users/lokesh/Documents/semgrep repo/demo_vulnerable_repo",
        "branch": "main",
        "commit_sha": val_res["resolved_commit_sha"],
        "scan_type": "SAST"
    }
    r = requests.post(f"{BASE_URL}/api/v1/scans/", json=scan_payload, headers={"X-Tenant-ID": "1"})
    assert r.status_code == 202, f"Scan creation failed: {r.text}"
    scan_job = r.json()
    scan_id = scan_job["id"]
    print(f"Enqueued Scan ID: {scan_id}, Initial Status: {scan_job['status']}")

    print("\n=== 4. Poll Celery Execution Telemetry ===")
    for i in range(60):
        time.sleep(2)
        r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers={"X-Tenant-ID": "1"})
        data = r.json()
        status = data["status"]
        print(f"[{i*2}s] Scan Status: {status}")
        if status in ["COMPLETED", "FAILED"]:
            break

    assert data["status"] == "COMPLETED", f"Scan did not complete: {data.get('error_message')}"
    print(f"Scan Completed Successfully! Findings: {data['finding_count']}, Files: {data['files_scanned']}")

    print("\n=== 5. Check Scanner Executions Telemetry ===")
    r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/scanners", headers={"X-Tenant-ID": "1"})
    scanners = r.json()
    print("Scanners Telemetry:", json.dumps(scanners, indent=2))
    assert len(scanners) > 0

    print("\n=== 6. Check Rules Validation & Language Coverage ===")
    r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/rules", headers={"X-Tenant-ID": "1"})
    rules = r.json()
    print("Rules Evaluated:", json.dumps(rules, indent=2))
    assert len(rules) > 0

    print("\n=== 7. Check Repository Profile ===")
    r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/profile", headers={"X-Tenant-ID": "1"})
    profile = r.json()
    print("Repository Profile:", json.dumps(profile, indent=2))
    assert len(profile["languages"]) > 0

    print("\n=== 8. Check Findings & Cross-Engine Provenance ===")
    r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/findings", headers={"X-Tenant-ID": "1"})
    findings = r.json()
    print(f"Total Findings Retrieved: {len(findings)}")
    for f in findings[:3]:
        print(f" - {f['severity']} [{f.get('finding_type')}]: {f['title']} (Detected by: {f.get('detected_by_scanners')})")

    print("\n=== 9. Check Raw MongoDB Artifact ===")
    r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/raw", headers={"X-Tenant-ID": "1"})
    raw_doc = r.json()
    print("Raw MongoDB Document Scanner:", raw_doc.get("scanner"), "Format:", raw_doc.get("format"))
    assert "raw_result" in raw_doc

    print("\n=== 10. Check Compliance Control Evaluations ===")
    r = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/compliance", headers={"X-Tenant-ID": "1"})
    evals = r.json()
    print("Compliance Controls Evaluated:", len(evals))
    for e in evals:
        print(f" - Control {e['control_id']}: {e['result']} ({e['reason']})")

    print("\n ALL UNIVERSAL REPOSITORY SECURITY PLATFORM GAPS VERIFIED WORKING!")

if __name__ == "__main__":
    main()
