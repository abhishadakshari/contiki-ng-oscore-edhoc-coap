#!/usr/bin/env python3
"""
Summarise one proxy-chain run into readable result files.

Reads the logs written by start-chain.sh (logs/server.log, logs/proxyN.log,
logs/chain.info) and, if it was captured, the client's output
(logs/client.log). Each run gets its own folder,
results/<N>-proxies_<date>_<time>/, holding:

  results.md    the readable report, with a table per request
  results.csv   one row per request, for spreadsheets and plots
  *.log         copies of the logs the report was made from

Every run is also added to results/all-runs.csv, for comparing runs.
and prints the new section to the terminal.

start-chain.sh runs this automatically when you stop the chain with Ctrl-C.
To run it by hand (from examples/java-nested):

  python3 summarise-chain.py
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

SERVER_PORT = 5675
PROXY_PORTS = [5685, 5695, 5705]
PROXY_IDS = ["AA", "BB", "CC"]

# Sizes measured on 20 Nov 2026 with the hello/1 request (bytes on the wire
# between the client and the first hop). Only valid for that request.
EXPECTED = {1: (28, 31), 2: (66, 42), 3: (104, 53), 4: (142, 64)}

UDP_LINE = re.compile(
    r"UDPConnector \((?P<label>.*?)\) (?P<dir>sent|received) (?P<n>\d+) bytes "
    r"(?:to|from) \[(?P<addr>[^\]]+)\]:(?P<port>\d+)")
FORWARD_LINE = re.compile(r"(?:ProxyCoapClientResource forwards |request was )(?P<type>CON|NON)")
DONE_LINE = re.compile(r"Remote Exchange\[R1, .*?\] completed (?:CON|NON|ACK|RST)-(?P<code>\d\.\d\d)")
JAVA_PROBLEM = re.compile(r" (ERROR|WARN) \[(?!Configuration)")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def read(path):
    try:
        with open(path, errors="replace") as f:
            return [ANSI.sub("", line.rstrip("\r\n").replace("\r", "")) for line in f]
    except OSError:
        return None


def parse_component(lines, own_port, next_port):
    """Split one Java log into the four directions, in order of appearance."""
    ev = {"req_in": [], "req_out": [], "resp_in": [], "resp_out": [], "codes": [], "types": [],
          "problems": []}
    for line in lines:
        m = UDP_LINE.search(line)
        if m:
            n = int(m.group("n"))
            port = int(m.group("port"))
            if m.group("dir") == "received":
                on_own_port = m.group("label").endswith("]:%d" % own_port)
                ev["req_in" if on_own_port else "resp_in"].append(n)
            else:
                ev["req_out" if port == next_port else "resp_out"].append(n)
            continue
        m = FORWARD_LINE.search(line)
        if m:
            ev["types"].append(m.group("type"))
            continue
        m = DONE_LINE.search(line)
        if m:
            ev["codes"].append(m.group("code"))
            continue
        if JAVA_PROBLEM.search(line):
            ev["problems"].append(line.strip())
    return ev


def parse_client(lines):
    info = {"layers": None, "chunk": None, "sent": [], "results": [], "notes": []}
    if lines is None:
        return None
    for i, line in enumerate(lines):
        m = re.search(r"Nested OSCORE client with (\d+) layers", line)
        if m:
            info["layers"] = int(m.group(1))
        m = re.search(r"COAP_MAX_CHUNK_SIZE\s*=\s*(\d+)", line)
        if m:
            info["chunk"] = int(m.group(1))
        m = re.search(r"Sending OSCORE message, len (\d+)", line)
        if m:
            info["sent"].append(int(m.group(1)))
        if line.strip() == "response:" and i + 1 < len(lines) and lines[i + 1].startswith("|"):
            info["results"].append(("ok", lines[i + 1][1:].strip()))
        m = re.search(r"No response: (.*)", line)
        if m:
            info["results"].append(("fail", m.group(1).strip() or "no reason given"))
        if re.search(r"\[(WARN|ERR) *: *(oscore|coap)", line):
            info["notes"].append(line.strip())
    return info


def parse_client_result(lines):
    """logs/client-result.txt, written by the client itself:
         start layers=4 chunk=160
         result OK Hello World!
         result FAILED <reason>"""
    info = {"layers": None, "chunk": None, "sent": [], "results": [], "notes": []}
    for line in lines:
        m = re.match(r"start layers=(\d+) chunk=(\d+)", line)
        if m:
            info["layers"], info["chunk"] = int(m.group(1)), int(m.group(2))
        m = re.match(r"result (OK|FAILED) ?(.*)", line)
        if m:
            info["results"].append(("ok" if m.group(1) == "OK" else "fail",
                                    m.group(2).strip() or "no reason given"))
    return info


def fresh(path, chain_start):
    """A client file belongs to this run if it was written to shortly before the
    chain started (the client starts first) or after."""
    try:
        return os.path.getmtime(path) >= chain_start - 60
    except OSError:
        return False


def fmt(v):
    return "—" if v is None else str(v)


def pick(lst, i):
    return lst[i] if i < len(lst) else None


def main():
    chain_info = {}
    for line in read(os.path.join(LOGS, "chain.info")) or []:
        if "=" in line:
            k, v = line.split("=", 1)
            chain_info[k.strip()] = v.strip()

    if "proxies" in chain_info:
        n_proxies = int(chain_info["proxies"])
    else:
        n_proxies = sum(os.path.exists(os.path.join(LOGS, "proxy%d.log" % k)) for k in (1, 2, 3))
    if not os.path.exists(os.path.join(LOGS, "server.log")):
        sys.exit("No server log in %s - run start-chain.sh first." % LOGS)
    started = chain_info.get("started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # One entry per hop, in order from the client: proxy 1 ... proxy N, server.
    hops = []
    for k in range(n_proxies):
        lines = read(os.path.join(LOGS, "proxy%d.log" % (k + 1))) or []
        nxt = PROXY_PORTS[k + 1] if k + 1 < n_proxies else SERVER_PORT
        hops.append(("proxy %d (ID %s, port %d)" % (k + 1, PROXY_IDS[k], PROXY_PORTS[k]),
                     parse_component(lines, PROXY_PORTS[k], nxt)))
    server = parse_component(read(os.path.join(LOGS, "server.log")) or [], SERVER_PORT, -1)
    hops.append(("server (port %d)" % SERVER_PORT, server))

    try:
        chain_start = datetime.strptime(started, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        chain_start = 0
    result_file = os.path.join(LOGS, "client-result.txt")
    client_log = os.path.join(LOGS, "client.log")
    if fresh(result_file, chain_start):
        client = parse_client_result(read(result_file))
    elif fresh(client_log, chain_start):
        client = parse_client(read(client_log))
    else:
        client = None
    layers = client["layers"] if client else None
    n_requests = max(len(hops[0][1]["req_in"]), len(client["sent"]) if client else 0)

    out = []
    title = "Run %s: %d prox%s" % (started, n_proxies, "y" if n_proxies == 1 else "ies")
    title += ", client %s layers" % (layers if layers else "?")
    out.append("## " + title)
    out.append("")
    if layers and layers != n_proxies + 1:
        out.append("**Mismatch:** the client has %d layers but the chain needs %d (proxies + 1)."
                   % (layers, n_proxies + 1))
        out.append("")
    if client is None:
        out.append("No client result for this run (logs/client-result.txt missing or older than the chain), "
                   "so the outcome at the client is unknown.")
        out.append("")
    elif client["chunk"]:
        out.append("COAP_MAX_CHUNK_SIZE on the client: %d" % client["chunk"])
        out.append("")
    if n_requests == 0:
        out.append("No request reached the first hop. Was the chain started within 20 s of the client?")
        out.append("")

    rows = []
    for i in range(n_requests):
        req = [pick(hops[0][1]["req_in"], i)] + [pick(h[1]["req_out"], i) for h in hops[:-1]]
        resp = [pick(h[1]["resp_out"], i) for h in hops]          # what each hop sent back
        resp = resp[::-1]                                           # server first ... proxy 1 last
        client_req = pick(client["sent"], i) if client else None
        client_req = client_req if client_req is not None else req[0]
        client_resp = resp[-1]
        result = pick(client["results"], i) if client else None
        req_type = pick(hops[0][1]["types"], i)
        short = None
        if result is None and req_type == "NON":
            short = ("NON: response delivered, not recordable" if client_resp is not None
                     else "NON: no response reached the client")
            if client_resp is not None:
                outcome = ("NON request: the response reached the client (%d bytes) but cannot be "
                           "recorded, because Contiki's blocking request API drops responses to NON "
                           "requests before the handler runs. Check the client's debug output for "
                           "the decrypted payload." % client_resp)
            else:
                outcome = "NON request: no response reached the client, and none can be recorded"
        elif result is None:
            outcome = "unknown (client log missing)" if client is None else "no response printed"
        elif result[0] == "ok":
            outcome = "OK: " + result[1]
        else:
            outcome = "FAILED: " + result[1]
        lost = next((hops[k][0] for k in range(len(hops)) if pick(hops[k][1]["req_in"], i) is None
                     and k > 0), None)

        exp = EXPECTED.get(layers) if layers else None
        if exp and client_req is not None and client_resp is not None:
            match = "yes" if (client_req, client_resp) == exp else "no (expected %d / %d)" % exp
        else:
            match = "n/a"

        out.append("### Request %d" % (i + 1))
        out.append("")
        out.append("- **Request type:** " + fmt(req_type))
        out.append("- **Outcome:** " + outcome)
        out.append("- **Client request / response:** %s / %s bytes" % (fmt(client_req), fmt(client_resp)))
        out.append("- **Matches expected sizes:** " + match)
        if lost:
            out.append("- **Request never reached:** " + lost)
        out.append("")
        out.append("| Link | Request bytes | Response bytes | Response code sent back |")
        out.append("| --- | --- | --- | --- |")
        names = ["client"] + [h[0].split(" (")[0] for h in hops]
        for k in range(len(hops)):
            code = pick(hops[k][1]["codes"], i)
            out.append("| %s → %s | %s | %s | %s |" % (
                names[k], names[k + 1], fmt(req[k]), fmt(resp[len(resp) - 1 - k]), fmt(code)))
        out.append("")
        rows.append({
            "run_started": started,
            "proxies": n_proxies,
            "client_layers": fmt(layers),
            "chunk_size": fmt(client["chunk"] if client else None),
            "request_no": i + 1,
            "client_request_bytes": fmt(client_req),
            "client_response_bytes": fmt(client_resp),
            "request_bytes_per_hop": " > ".join(fmt(x) for x in req),
            "response_bytes_per_hop": " > ".join(fmt(x) for x in resp),
            "request_type": fmt(req_type),
            "server_code": fmt(pick(server["codes"], i)),
            "outcome": short or outcome,
            "matches_expected": match,
        })

    notes = []
    if client:
        notes += ["client: " + n for n in client["notes"]]
    for name, ev in hops:
        notes += ["%s: %s" % (name.split(" (")[0], p) for p in ev["problems"]]
    if notes:
        out.append("### Warnings and errors")
        out.append("")
        out += ["- `%s`" % n[:200] for n in notes[:20]]
        if len(notes) > 20:
            out.append("- ... %d more, see the .log files in this folder" % (len(notes) - 20))
        out.append("")

    # Each run gets its own folder: results/<N>-proxies_<date>_<time>/
    stamp = started.replace(" ", "_").replace(":", "-")
    run_name = "%d-prox%s_%s" % (n_proxies, "y" if n_proxies == 1 else "ies", stamp)
    run_dir = os.path.join(RESULTS, run_name)
    os.makedirs(run_dir, exist_ok=True)

    with open(os.path.join(run_dir, "results.md"), "w") as f:
        f.write("# Proxy chain results\n\n"
                "Sizes are bytes on the wire for each link. The response code is the "
                "outer code each hop sent back: OSCORE hides the real code (2.05 Content) "
                "inside, so 2.04 means success, while an unprotected error such as 4.01 "
                "shows here as it is.\n\n")
        f.write("\n".join(out) + "\n")

    if rows:
        with open(os.path.join(run_dir, "results.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        # Every run is also added to one combined table, for comparing runs.
        all_csv = os.path.join(RESULTS, "all-runs.csv")
        new_all = not os.path.exists(all_csv)
        with open(all_csv, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            if new_all:
                w.writeheader()
            w.writerows(rows)

    # Keep the raw logs with the results, since logs/ is reused by the next run.
    for name in os.listdir(LOGS):
        if name.endswith(".log") or name in ("chain.info", "client-result.txt"):
            shutil.copy(os.path.join(LOGS, name), os.path.join(run_dir, name))

    print("\n".join(out))
    print("Saved to results/%s/ (results.md, results.csv and the logs)" % run_name)
    if rows:
        print("Also added to results/all-runs.csv")


if __name__ == "__main__":
    main()
