"""Run the M8 red-team demo and print a judge-readable report.

    python -m backend.redteam
"""
from __future__ import annotations

import logging
import sys

from backend.redteam import run_all

BOLD, GREEN, RED, DIM, RESET = "\033[1m", "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def main() -> int:
    logging.disable(logging.WARNING)      # the injection tripwire logs on purpose
    print(f"\n{BOLD}DCTA — red-team demo (M8){RESET}")
    print(f"{DIM}Every scenario runs against the real pipeline over the real API."
          f"\nGenAI is a generator of drafts, never an executor of funds.{RESET}\n")

    results = run_all()
    for r in results:
        mark = f"{GREEN}HELD{RESET}" if r.passed else f"{RED}FAILED{RESET}"
        print(f"{BOLD}{r.number}. {r.name}{RESET}  [{mark}]")
        print(f"   {DIM}attack:{RESET}   {r.attack}")
        print(f"   {DIM}property:{RESET} {r.property_}")
        for line in r.evidence:
            print(f"     · {line}")
        print()

    held = sum(1 for r in results if r.passed)
    ok = held == len(results)
    colour = GREEN if ok else RED
    print(f"{BOLD}{colour}{held}/{len(results)} properties held{RESET}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
