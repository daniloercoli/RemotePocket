"""Report candidate locations without printing credential values."""
import json
import sys

count = 0
for filename in sys.argv[1:]:
    with open(filename, encoding="utf-8") as report:
        for line in report:
            finding = json.loads(line)
            metadata = finding.get("SourceMetadata", {}).get("Data", {})
            source = metadata.get("Git") or metadata.get("Filesystem") or {}
            path = source.get("file", "unknown")
            # Reviewed placeholder in a deleted documentation example, not a credential.
            if (finding.get("Raw") == "postgresql://" + "user:pass@host:5432"
                    and path == "Server/docs/SECRET_MANAGEMENT.md"
                    and finding.get("DetectorName") == "Postgres"):
                continue
            count += 1
            print(f"Secret candidate: {finding.get('DetectorName')} at {path}:{source.get('line', '?')}")
print(f"Unexpected secret candidates: {count}")
sys.exit(1 if count else 0)
