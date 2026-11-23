"""Collect live evidence and require a pass for every integration check."""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

import live
import live_binding
import live_logo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--lab-evidence", type=Path)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    common = ["--binary", args.binary, "--evidence", str(args.evidence)]
    drivers = [
        ["live.py", "--case", case, "--message", message]
        for case in live.IDS for message in live.MESSAGES
    ]
    drivers.append(["discovery_runs.py"])
    drivers.extend(
        ["live_binding.py", "--case", case, "--message", message]
        for case, messages in live_binding.CASES.items() for message in messages
    )
    drivers.extend(["live_logo.py", "--part", part] for part in live_logo.OBSERVATION_SECONDS)

    failed = False
    for command in drivers:
        # Keep collecting so a failure does not prevent later cases from running.
        result = subprocess.run([sys.executable, "-B", *command, *common], check=False)
        failed |= result.returncode != 0

    if args.lab_evidence:
        for source in args.lab_evidence.glob("*/*.json"):
            destination = args.evidence / source.parent.name / source.name
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

    verdict = subprocess.call([
        sys.executable, "-B", "run.py", "--require-all-pass",
        "--evidence", str(args.evidence), "--report", str(args.evidence / "report.json"),
    ])
    return verdict or int(failed)


if __name__ == "__main__":
    sys.exit(main())
