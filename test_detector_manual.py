"""
Manual test script to debug the Prompt Injection detector.

Run this to see detailed output from the detector.
"""

import asyncio
from src.core.runner import run_assessment
from src.core.models import DetectionStatus


async def main():
    print("=" * 80)
    print("MCP Security Framework - Manual Detector Test")
    print("=" * 80)

    # Run assessment
    print("\n[1] Running assessment against DV-MCP Challenge 1...")
    result = await run_assessment(
        "samples/scope.yaml",
        detector_ids=["MCP-2024-PI-001"],
    )

    print(f"\n[2] Assessment completed:")
    print(f"    Assessment ID: {result.assessment_id}")
    print(f"    Server: {result.profile.server_name}")
    print(f"    Started: {result.started_at}")
    print(f"    Completed: {result.completed_at}")

    print(f"\n[3] Detection Results:")
    for i, res in enumerate(result.results, 1):
        print(f"\n    Result #{i}:")
        print(f"      Detector: {res.detector_name} ({res.detector_id})")
        print(f"      Status: {res.status.value}")
        print(f"      Confidence: {res.confidence:.0%}")
        print(f"      Affected Resources: {res.affected_resources}")
        print(f"      Signals: {len(res.signals)}")

        if res.signals:
            for sig in res.signals:
                sig_type = sig.type.value if hasattr(sig.type, 'value') else sig.type
                print(f"        - {sig_type}: {sig.value}")

        print(f"      Evidence: {res.evidence}")

        if res.remediation:
            print(f"      Remediation: {res.remediation[:100]}...")

    print(f"\n[4] Summary:")
    print(f"    Present: {result.summary.get('present', 0)}")
    print(f"    Absent: {result.summary.get('absent', 0)}")
    print(f"    Unknown: {result.summary.get('unknown', 0)}")
    print(f"    Not Applicable: {result.summary.get('not_applicable', 0)}")

    print(f"\n[5] Audit Log: {result.audit_log_path}")

    print("\n" + "=" * 80)

    # Check if we detected the vulnerability
    pi_result = next(
        (r for r in result.results if r.detector_id == "MCP-2024-PI-001"),
        None
    )

    if pi_result and pi_result.status == DetectionStatus.PRESENT:
        print("[SUCCESS] Challenge 1 vulnerability detected!")
        return 0
    else:
        print("[FAILED] Challenge 1 vulnerability NOT detected")
        if pi_result:
            print(f"  Status was: {pi_result.status.value}")
            print(f"  Evidence: {pi_result.evidence}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
