import json
import sys
import os

from shared.report_contract import verify_checksum, validate_report

def check_secrets(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = k.lower()
            if 'password' in kl or 'cookie' in kl or 'token' in kl:
                print(f"ERROR: Prohibited secret field found: {k}", file=sys.stderr)
                sys.exit(1)
            check_secrets(v)
    elif isinstance(obj, list):
        for item in obj:
            check_secrets(item)

def main():
    if len(sys.argv) < 2:
        print("ERROR: Report path required", file=sys.stderr)
        sys.exit(1)
        
    report_path = sys.argv[1]
    
    if not os.path.isfile(report_path):
        print(f"ERROR: Report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if not validate_report(report_data):
        print("ERROR: Schema validation failed", file=sys.stderr)
        sys.exit(1)

    if not verify_checksum(report_data):
        print("ERROR: Checksum validation failed", file=sys.stderr)
        sys.exit(1)

    check_secrets(report_data)
    
    print("Verification successful.")
    sys.exit(0)

if __name__ == '__main__':
    main()
