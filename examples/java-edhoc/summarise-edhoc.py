#!/usr/bin/env python3
"""
Summarise one Stage 1 run (Contiki client <-> Java EdhocServer) into readable
result files.

Reads logs/server.log (the Java server's output, written by
start-edhoc-server.sh), logs/run.info and logs/client-result.txt (written by
the Contiki client). Each run gets its own folder,
results/stage1_<date>_<time>/, holding:

  results.md    the readable report
  results.csv   one row for the run, for spreadsheets and plots
  *.log, *.txt  copies of the files the report was made from

Every run is also added to results/all-runs.csv, for comparing runs.

start-edhoc-server.sh runs this when you stop the server with Ctrl-C.
To run it by hand (from examples/java-edhoc):  python3 summarise-edhoc.py
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

# What the n-th request / response on the server is, in Stage 1
NAMES = [("EDHOC message_1", "EDHOC message_2"),
         ("EDHOC message_3", "response to message_3"),
         ("OSCORE request (GET /helloWorld)", "OSCORE response")]


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


def main():
    info = {}
    for line in read(os.path.join(LOGS, "run.info")) or []:
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    started = info.get("started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    stage = info.get("stage", "1")
    try:
        start_ts = datetime.strptime(started, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        start_ts = 0

    server = read(os.path.join(LOGS, "server.log"))
    if server is None:
        sys.exit("No logs/server.log - run start-edhoc-server.sh first.")

    # Messages between the client and the server, in order.
    # A 4-byte message is either an empty ACK (not counted) or a real response
    # with no token and no payload, e.g. the "ACK-2.04" the server sends back
    # for message_3. Californium logs "completed ACK-2.04 ... <empty data>" just
    # before sending the latter, which is how the two are told apart.
    rx, tx, acks, problems = [], [], 0, []
    last_empty_response = -1000
    for i, line in enumerate(server):
        if EMPTY_RESPONSE.search(line):
            last_empty_response = i
            continue
        m = UDP_LINE.search(line)
        if m:
            n = int(m.group("n"))
            if n == EMPTY_ACK and m.group("dir") == "sent" and i - last_empty_response > 40:
                acks += 1
            elif n == EMPTY_ACK and m.group("dir") == "received":
                acks += 1
            elif m.group("dir") == "received":
                rx.append((m.group("time"), n))
            else:
                tx.append((m.group("time"), n))
            continue
        if PROBLEM.search(line):
            problems.append(line.strip())

    # The client's own view of the run
    client = {"chunk": None, "method": None, "edhoc": None, "ids": None, "result": None}
    cfile = os.path.join(LOGS, "client-result.txt")
    clines = read(cfile) if fresh(cfile, start_ts) else None
    for line in clines or []:
        m = re.match(r"start .*chunk=(\d+)(?: method=(\d+))?", line)
        if m:
            client["chunk"], client["method"] = m.group(1), m.group(2)
        m = re.match(r"edhoc (OK|FAILED) ?(.*)", line)
        if m:
            client["edhoc"] = m.group(1)
            client["ids"] = m.group(2)
        m = re.match(r"result (OK|FAILED) ?(.*)", line)
        if m:
            client["result"] = ("OK: " if m.group(1) == "OK" else "FAILED: ") + m.group(2)

    if clines is None:
        outcome = "unknown (no client-result.txt for this run)"
    elif client["edhoc"] == "FAILED":
        outcome = "EDHOC failed (%s)" % client["ids"]
    elif client["edhoc"] is None:
        outcome = "EDHOC did not finish"
    else:
        outcome = client["result"] or "EDHOC finished, no response to the OSCORE request"

    out = ["## Stage %s run %s" % (stage, started), ""]
    out.append("- **Outcome:** " + outcome)
    out.append("- **EDHOC:** %s%s" % (fmt(client["edhoc"]),
               ("  (" + client["ids"] + ")") if client["edhoc"] == "OK" else ""))
    out.append("- **Method / suite / chunk size:** %s / 2 / %s" % (fmt(client["method"]), fmt(client["chunk"])))
    if acks:
        out.append("- **Empty ACKs (4 bytes, no code), not counted below:** %d" % acks)
    out.append("")
    out.append("| Step | Client → server (bytes) | Server → client (bytes) |")
    out.append("| --- | --- | --- |")
    rows = max(len(rx), len(tx))
    for i in range(rows):
        names = NAMES[i] if i < len(NAMES) else ("request %d" % (i + 1), "response %d" % (i + 1))
        r = rx[i][1] if i < len(rx) else None
        t = tx[i][1] if i < len(tx) else None
        out.append("| %s / %s | %s | %s |" % (names[0], names[1], fmt(r), fmt(t)))
    if rows > len(NAMES):
        out.append("")
        out.append("More messages than expected: probably retransmissions (check the timestamps in server.log).")
    edhoc_total = sum(n for _, n in rx[:2]) + sum(n for _, n in tx[:2])
    out.append("")
    out.append("Total EDHOC bytes on the wire (messages 1-3 and the reply to 3): %d" % edhoc_total)
    out.append("")
    if problems:
        out.append("### Warnings and errors (server)")
        out.append("")
        out += ["- `%s`" % p[:200] for p in problems[:20]]
        out.append("")

    def at(lst, i):
        return lst[i][1] if i < len(lst) else None

    row = {
        "run_started": started, "stage": stage, "method": fmt(client["method"]),
        "chunk_size": fmt(client["chunk"]), "edhoc": fmt(client["edhoc"]),
        "msg1": fmt(at(rx, 0)), "msg2": fmt(at(tx, 0)), "msg3": fmt(at(rx, 1)),
        "msg3_reply": fmt(at(tx, 1)), "edhoc_total": edhoc_total,
        "oscore_request": fmt(at(rx, 2)), "oscore_response": fmt(at(tx, 2)),
        "empty_acks": acks, "outcome": outcome,
    }

    run_dir = os.path.join(RESULTS, "stage%s_%s" % (stage, started.replace(" ", "_").replace(":", "-")))
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "results.md"), "w") as f:
        f.write("# EDHOC + OSCORE results\n\nSizes are bytes on the wire between the client "
                "and the server, read from the server's log.\n\n")
        f.write("\n".join(out) + "\n")
    with open(os.path.join(run_dir, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerow(row)
    all_csv = os.path.join(RESULTS, "all-runs.csv")
    new = not os.path.exists(all_csv)
    with open(all_csv, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)
    for name in ("server.log", "run.info", "client-result.txt"):
        p = os.path.join(LOGS, name)
        if os.path.exists(p):
            shutil.copy(p, os.path.join(run_dir, name))

    print("\n".join(out))
    print("Saved to results/%s/ and added to results/all-runs.csv" % os.path.basename(run_dir))


if __name__ == "__main__":
    main()
