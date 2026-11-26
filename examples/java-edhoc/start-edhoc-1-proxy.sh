#!/bin/sh
# Compile and start the Java EDHOC server AND the Java EDHOC proxy for Stage 2
# (one proxy), and record the run.
#
# Run inside the contiker container, from examples/java-edhoc, AFTER the
# Contiki client (examples/oscore-edhoc-1-proxy) is running - it creates
# fd00::1 on tun0, which both Java programs bind to:
#   sh start-edhoc-1-proxy.sh
# Stop the client first, then Ctrl-C here: the run is summarised into
# results/stage2_<date>_<time>/ by summarise-edhoc-proxy.py.
cd "$(dirname "$0")"

echo "Compiling..."
mkdir -p classes
javac -nowarn -cp lib/OscoreCapableProxy.jar -d classes $(find src -name '*.java') || exit 1

mkdir -p logs
# Old logs would be mistaken for this run (client-result.txt is left alone:
# the client is already writing to it).
rm -f logs/server.log logs/proxy.log
printf 'stage=2\nstarted=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" > logs/run.info

CP=classes:lib/OscoreCapableProxy.jar
finish() {
  kill $SPID $PPID2 2>/dev/null
  echo "stopped"
  python3 summarise-edhoc-proxy.py || echo "(could not summarise the run)"
  exit 0
}
trap finish INT TERM

java -cp $CP org.eclipse.californium.edhoc.capable.EdhocServer > logs/server.log 2>&1 &
SPID=$!
java -cp $CP org.eclipse.californium.edhoc.capable.EdhocProxy > logs/proxy.log 2>&1 &
PPID2=$!
sleep 4
if grep -q "BindException" logs/server.log logs/proxy.log; then
  echo "Could not bind to fd00::1 - start the Contiki client first."
  kill $SPID $PPID2 2>/dev/null
  exit 1
fi
echo "EDHOC server [fd00::1]:5686  log: logs/server.log"
echo "EDHOC proxy  [fd00::1]:5685  log: logs/proxy.log"
echo "Waiting (Ctrl-C stops both and writes results/)..."
wait
