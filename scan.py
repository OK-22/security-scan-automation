#!/usr/bin/env python3
"""Run an Nmap service scan and write normalized JSON: {"host:port/proto": "service"}."""
import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

DEFAULT_PORTS = "22,80,135,443,445,3389,8080"


def run_nmap(targets, ports):
    cmd = ["nmap", "-sV", "-p", ports, "-oX", "-"] + targets
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"nmap failed: {r.stderr.strip()}")
    return r.stdout


def parse(xml_text):
    root = ET.fromstring(xml_text)
    result = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = next(
            (a.get("addr") for a in host.findall("address")
             if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if not addr:
            continue
        for port in host.findall("ports/port"):
            if port.find("state").get("state") != "open":
                continue
            svc = port.find("service")
            parts = []
            if svc is not None:
                parts = [svc.get(k, "") for k in ("name", "product", "version")]
            key = f"{addr}:{port.get('portid')}/{port.get('protocol')}"
            result[key] = " ".join(p for p in parts if p).strip() or "unknown"
    return dict(sorted(result.items()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--ports", default=DEFAULT_PORTS)
    ap.add_argument("--out", default="results/latest.json")
    args = ap.parse_args()

    scan = parse(run_nmap(args.targets, args.ports))
    with open(args.out, "w") as f:
        json.dump(scan, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"{len(scan)} open ports written to {args.out}")


if __name__ == "__main__":
    main()
