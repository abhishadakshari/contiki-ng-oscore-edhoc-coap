#!/usr/bin/env python3
"""
Summarise one Stage 2 run (Contiki client -> Java EdhocProxy -> Java
EdhocServer) into readable result files.

Reads logs/proxy.log and logs/server.log (written by start-edhoc-1-proxy.sh),
logs/run.info and logs/client-result.txt (written by the Contiki client).
Each run gets its own folder, results/stage2_<date>_<time>/, holding:

  results.md    the readable report
  results.csv   one row for the run, for spreadsheets and plots
  *.log, *.txt  copies of the files the report was made from

Every run is also added to results/all-runs-stage2.csv (Stage 2 has more
columns than Stage 1, so it has its own file).

start-edhoc-1-proxy.sh runs this when you stop it with Ctrl-C.
To run it by hand (from examples/java-edhoc):  python3 summarise-edhoc-proxy.py
"""
import csv
import os
import re
import shutil
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "logs")
RESULTS = os.path.join(HERE, "results")
SERVER_PORT = 5686
EMPTY_ACK = 4          # an empty CoAP ACK is 4 bytes

UDP_LINE = re.compile(
    r"^(?P<time>\d\d:\d\d:\d\d\.\d+) .*UDPConnector \((?P<label>.*?)\) (?P<dir>sent|received) "
    r"(?P<n>\d+) bytes (?:to|from) \[(?P<addr>[^\]]+)\]:(?P<port>\d+)")
EMPTY_RESPONSE = re.compile(r"completed ACK-\d\.\d\d .*<empty data>")
PROBLEM = re.compile(r" (ERROR|WARN) \[(?!Configuration|EdhocLayer)")
ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Client <-> proxy: what the n-th request / response is
CLIENT_NAMES = [
    ("EDHOC 1 (proxy): message_1", "message_2"),
    ("EDHOC 1 (proxy): message_3", "reply to message_3"),
    ("EDHOC 2 (server, via proxy, in proxy's OSCORE): message_1", "message_2"),
    ("EDHOC 2 (server, via proxy, in proxy's OSCORE): message_3", "reply to message_3"),
    ("GET /helloWorld, 2 OSCORE layers", "response, 2 layers"),
]
# Proxy <-> server (read from the server's log)
SERVER_NAMES = [
    ("EDHOC 2: message_1", "message_2"),
    ("EDHOC 2: message_3", "reply to message_3"),
    ("GET /helloWorld, 1 OSCORE layer (server's)", "response, 1 layer"),
]


def read(path):
    try:
        with open(path, errors="replace") as f:
            return [ANSI.sub("", l.rstrip("\r\n")) for l in f]
    except OSError:
        return None


def fresh(path, start):
    try:
        return os.path.getmtime(path) >= start - 60
    except OSError:
        return False


def fmt(v):
    return "—" if v is None else str(v)


def messages(lines, keep):
    """Requests received and responses sent, in order, for the UDP lines that
    keep(port) accepts. 4-byte messages are empty ACKs unless Californium has
    just logged an empty-payload response (e.g. the ACK-2.04 to message_3)."""
    rx, tx, acks, problems = [], [], 0, []
    last_empty_response = -1000
    for i, line in enumerate(lines):
        if EMPTY_RESPONSE.search(line):
            last_empty_response = i
            continue
        m = UDP_LINE.search(line)
        if m:
            if not keep(int(m.group("port"))):
                continue
            n = int(m.group("n"))
            if n == EMPTY_ACK and (m.group("dir") == "received" or i - last_empty_response > 40):
                acks += 1
            elif m.group("dir") == "received":
                rx.append(n)
            else:
                tx.append(n)
            continue
        if PROBLEM.search(line):
            problems.append(line.strip())
    return rx, tx, acks, problems


def table(title, left, right, names, rx, tx):
    out = ["### " + title, "", "| Step | %s (bytes) | %s (bytes) |" % (left, right), "| --- | --- | --- |"]
    rows = max(len(rx), len(tx))
    for i in range(rows):
        nm = names[i] if i < len(names) else ("request %d" % (i + 1), "response %d" % (i + 1))
        out.append("| %s / %s | %s | %s |" % (nm[0], nm[1], fmt(rx[i] if i < len(rx) else None),
                                             fmt(tx[i] if i < len(tx) else None)))
    if rows > len(names):
        out += ["", "More messages than expected: probably retransmissions (check the timestamps in the log)."]
    out.append("")
    return out


def main():
    info = {}
    for line in read(os.path.join(LOGS, "run.info")) or []:
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    started = info.get("started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    stage = info.get("stage", "2")
    try:
        start_ts = datetime.strptime(started, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        start_ts = 0

    proxy = read(os.path.join(LOGS, "proxy.log"))
    server = read(os.path.join(LOGS, "server.log"))
    if proxy is None or server is None:
        sys.exit("No logs/proxy.log or logs/server.log - run start-edhoc-1-proxy.sh first.")

    # In the proxy's log, anything to/from port 5686 is the proxy -> server link
    c_rx, c_tx, c_acks, p_problems = messages(proxy, lambda port: port != SERVER_PORT)
    s_rx, s_tx, s_acks, s_problems = messages(server, lambda port: True)

    # The client's own view of the run
    client = {"chunk": None, "method": None, "edhoc1": None, "edhoc2": None, "result": None}
    cfile = os.path.join(LOGS, "client-result.txt")
    clines = read(cfile) if fresh(cfile, start_ts) else None
    for line in clines or []:
        m = re.match(r"start .*chunk=(\d+)(?: method=(\d+))?", line)
        if m:
            client["chunk"], client["method"] = m.group(1), m.group(2)
        m = re.match(r"edhoc([12]) (OK|FAILED) ?(.*)", line)
        if m:
            client["edhoc" + m.group(1)] = (m.group(2), m.group(3))
        m = re.match(r"result (OK|FAILED) ?(.*)", line)
        if m:
            client["result"] = ("OK: " if m.group(1) == "OK" else "FAILED: ") + m.group(2)

    def edhoc_text(k):
        v = client[k]
        if v is None:
            return "did not finish"
        return v[0] + ("  (" + v[1] + ")" if v[1] else "")

    if clines is None:
        outcome = "unknown (no client-result.txt for this run)"
    elif client["edhoc1"] is None or client["edhoc1"][0] != "OK":
        outcome = "EDHOC with the proxy " + edhoc_text("edhoc1")
    elif client["edhoc2"] is None or client["edhoc2"][0] != "OK":
        outcome = "EDHOC with the server (via the proxy) " + edhoc_text("edhoc2")
    else:
        outcome = client["result"] or "both EDHOC runs finished, no response to the OSCORE request"

    # The proxy and the server use different C_R values (0x11 and 0x27), so
    # if both runs report the same Sender ID the second handshake never
    # really ran with the server: the client reused the first run's state.
    warnings = []
    if (client["edhoc1"] and client["edhoc2"] and client["edhoc1"][0] == "OK"
            and client["edhoc2"][0] == "OK"):
        sid1 = re.search(r"sid=(\w+)", client["edhoc1"][1] or "")
        sid2 = re.search(r"sid=(\w+)", client["edhoc2"][1] or "")
        if sid1 and sid2 and sid1.group(1) == sid2.group(1):
            warnings.append("EDHOC 2 has the same Sender ID as EDHOC 1 (%s): the second handshake "
                            "did not run with the server, so the tables below are not EDHOC 2." % sid1.group(1))

    out = ["## Stage %s run %s (1 proxy)" % (stage, started), ""]
    out.append("- **Outcome:** " + outcome)
    out.append("- **EDHOC 1, client ↔ proxy:** " + edhoc_text("edhoc1"))
    out.append("- **EDHOC 2, client ↔ server via proxy:** " + edhoc_text("edhoc2"))
    for w in warnings:
        out.append("- **Warning:** " + w)
    out.append("- **Method / suite / chunk size:** %s / 2 / %s" % (fmt(client["method"]), fmt(client["chunk"])))
    if c_acks or s_acks:
        out.append("- **Empty ACKs (4 bytes, no code), not counted below:** client link %d, server link %d"
                   % (c_acks, s_acks))
    out.append("")
    out += table("Client ↔ proxy (read from proxy.log)", "Client → proxy", "Proxy → client",
                 CLIENT_NAMES, c_rx, c_tx)
    out += table("Proxy ↔ server (read from server.log)", "Proxy → server", "Server → proxy",
                 SERVER_NAMES, s_rx, s_tx)

    def total(rx, tx, a, b):
        return sum(rx[a:b]) + sum(tx[a:b])
    e1 = total(c_rx, c_tx, 0, 2)
    e2_client = total(c_rx, c_tx, 2, 4)
    e2_server = total(s_rx, s_tx, 0, 2)
    out.append("EDHOC bytes on the wire (messages 1-3 and the reply to 3):")
    out.append("")
    out.append("- EDHOC 1, client ↔ proxy: %d" % e1)
    out.append("- EDHOC 2, client ↔ proxy leg (inside the proxy's OSCORE): %d" % e2_client)
    out.append("- EDHOC 2, proxy ↔ server leg (plain EDHOC): %d" % e2_server)
    out.append("- Extra per EDHOC 2 round trip for the proxy's OSCORE layer: %d bytes over 4 messages"
               % (e2_client - e2_server))
    out.append("")
    problems = [("proxy", p) for p in p_problems] + [("server", p) for p in s_problems]
    if problems:
        out.append("### Warnings and errors")
        out.append("")
        out += ["- %s: `%s`" % (who, p[:200]) for who, p in problems[:20]]
        out.append("")

    def at(lst, i):
        return fmt(lst[i] if i < len(lst) else None)

    row = {
        "run_started": started, "stage": stage, "method": fmt(client["method"]),
        "chunk_size": fmt(client["chunk"]),
        "edhoc1": client["edhoc1"][0] if client["edhoc1"] else "—",
        "edhoc2": client["edhoc2"][0] if client["edhoc2"] else "—",
        "e1_msg1": at(c_rx, 0), "e1_msg2": at(c_tx, 0), "e1_msg3": at(c_rx, 1), "e1_msg3_reply": at(c_tx, 1),
        "e2_msg1_client": at(c_rx, 2), "e2_msg2_client": at(c_tx, 2),
        "e2_msg3_client": at(c_rx, 3), "e2_msg3_reply_client": at(c_tx, 3),
        "e2_msg1_server": at(s_rx, 0), "e2_msg2_server": at(s_tx, 0),
        "e2_msg3_server": at(s_rx, 1), "e2_msg3_reply_server": at(s_tx, 1),
        "edhoc1_total": e1, "edhoc2_total_client_leg": e2_client, "edhoc2_total_server_leg": e2_server,
        "oscore_request_client": at(c_rx, 4), "oscore_response_client": at(c_tx, 4),
        "oscore_request_server": at(s_rx, 2), "oscore_response_server": at(s_tx, 2),
        "outcome": outcome,
    }

    run_dir = os.path.join(RESULTS, "stage%s_%s" % (stage, started.replace(" ", "_").replace(":", "-")))
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "results.md"), "w") as f:
        f.write("# EDHOC + nested OSCORE results, 1 proxy\n\nSizes are bytes on the wire, read from "
                "the proxy's log (client side) and the server's log (server side).\n\n")
        f.write("\n".join(out) + "\n")
    with open(os.path.join(run_dir, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerow(row)
    all_csv = os.path.join(RESULTS, "all-runs-stage2.csv")
    new = not os.path.exists(all_csv)
    with open(all_csv, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)
    for name in ("proxy.log", "server.log", "run.info", "client-result.txt"):
        p = os.path.join(LOGS, name)
        if os.path.exists(p):
            shutil.copy(p, os.path.join(run_dir, name))

    print("\n".join(out))
    print("Saved to results/%s/ and added to results/all-runs-stage2.csv" % os.path.basename(run_dir))


if __name__ == "__main__":
    main()
