"""Run DHCPv6 conformance checks against captures from an integration run."""

import argparse
from collections import Counter
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sys
import traceback

from catalog import CATALOG
from conformance import Inconclusive, NotApplicable, Trace

ROOT = Path(__file__).resolve().parent


def load_check(path):
    spec = spec_from_file_location(f"{path.parent.name}_{path.stem}", path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", help="exact catalog ID, e.g. DC-01-001")
    parser.add_argument("--message", help="message variant, e.g. solicit")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--describe", metavar="DC-ID",
                        help="show the catalog stimulus, expected observation and reference")
    parser.add_argument("--evidence", type=Path, help="directory of per-case capture JSON files")
    parser.add_argument("--report", type=Path, help="write machine-readable results")
    parser.add_argument("--require-all-pass", action="store_true",
                        help="fail unless every selected check reports PASS")
    args = parser.parse_args()
    if not __debug__:
        parser.error("the checks require assertions; run without -O")
    if args.describe:
        if args.describe not in CATALOG:
            parser.error("unknown catalog ID")
        print(json.dumps(CATALOG[args.describe], ensure_ascii=False, indent=2))
        return 0
    if not args.list and not args.evidence:
        parser.error("supply --evidence or --list")
    cases = [p for p in sorted(ROOT.glob("DC-*/*/test_*.py"))
             if (not args.case or p.parent.name == args.case)
             and (not args.message or p.stem[5:] == args.message)]
    if not cases:
        parser.error("no matching case and message")
    results = []
    for path in cases:
        case, message = path.parent.name, path.stem[5:]
        if args.list:
            print(case, message)
            continue
        evidence = args.evidence / case / (message + ".json")
        verdict, detail = "PASS", ""
        data = {}
        try:
            check = load_check(path)
            data = json.loads(evidence.read_text(encoding="utf-8"))
            if data["case"] != case or data["message"] != message:
                raise Inconclusive("evidence identifies another case or variant")
            check(Trace(data))
        except AssertionError as error:
            last = traceback.extract_tb(error.__traceback__)[-1]
            verdict, detail = "FAIL", str(error) or f"{Path(last.filename).name}:{last.lineno} {last.line}"
        except NotApplicable as error:
            verdict, detail = "N/A", str(error)
        except (Inconclusive, KeyError, FileNotFoundError) as error:
            verdict, detail = "INCONCLUSIVE", str(error)
        except Exception as error:
            verdict, detail = "ERROR", f"{type(error).__name__}: {error}"
        print(f"{verdict:12} {case} {message} {detail}")
        metadata = CATALOG.get(case, {"reference": f"IPv6 Ready Logo {case}"})
        results.append(dict(case=case, message=message, verdict=verdict,
                            detail=detail, evidence=str(evidence), objective=metadata,
                            dut=data.get("dut") if isinstance(data, dict) else None))
    if args.list:
        return 0
    if args.report:
        args.report.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    totals = Counter(row["verdict"] for row in results)
    print("  ".join(f"{name}={n}" for name, n in sorted(totals.items())))
    if args.require_all_pass and totals["PASS"] != len(results):
        return 1
    if totals["FAIL"] or totals["ERROR"]:
        return 1
    return 2 if totals["INCONCLUSIVE"] or not totals["PASS"] else 0


if __name__ == "__main__":
    sys.exit(main())
