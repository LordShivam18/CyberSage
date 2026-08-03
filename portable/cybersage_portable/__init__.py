"""
cybersage_portable — CyberSage Portable Security Assessment

IMPORTANT DISCLAIMER
====================
This tool assesses the security posture of the current device for prioritization
purposes only.  It does not guarantee, certify, or prove that the device is
secure.  No scanner can detect every threat.  Findings must be interpreted by a
qualified person.  This tool performs no automatic remediation.

Safe-use rules enforced by design
----------------------------------
* Read-only collection — no registry writes, no process termination, no file
  deletion, no firewall changes, no configuration changes.
* No credential, password-hash, cookie, token, private-key, clipboard, or
  document content is collected.
* No telemetry is uploaded automatically.
* No network scanning of remote hosts is performed.
* No kernel driver is installed.
"""

__version__ = "1.0.0"
__schema_version__ = "assessment.v1"
__score_algorithm__ = "posture_score_v1"

DISCLAIMER = (
    "CyberSage Portable Security Assessment v1 — for prioritization purposes only. "
    "No scanner guarantees complete security. "
    "No automatic remediation is performed. "
    "All collection is read-only."
)
