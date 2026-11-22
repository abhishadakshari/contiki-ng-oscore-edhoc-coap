#!/bin/sh
# Compile and start the Java EDHOC server for Stage 1 and record the run.
#
# Run inside the contiker container, from examples/java-edhoc, AFTER the
# Contiki client is running (it creates fd00::1 on tun0):
#   sh start-edhoc-server.sh
# Stop the client first, then Ctrl-C here: the run is summarised into
# results/stage1_<date>_<time>/ by summarise-edhoc.py.
cd "$(dirname "$0")"

echo "Compiling..."
mkdir -p classes
javac -nowarn -cp lib/OscoreCapableProxy.jar -d classes $(find src -name '*.java') || exit 1

mkdir -p logs
# Old server logs would be mistaken for this run (client-result.txt is left
# alone: the client is already writing to it).
rm -f logs/server.log
printf 'stage=1\nstarted=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" > logs/run.info

finish() {
  kill $PID 2>/dev/null
  echo "stopped"
  python3 summarise-edhoc.py || echo "(could not summarise the run)"
  exit 0
}
trap finish INT TERM

java -cp classes:lib/OscoreCapableProxy.jar org.eclipse.californium.edhoc.capable.EdhocServer \
     > logs/server.log 2>&1 &
PID=$!
sleep 3
if grep -q "BindException" logs/server.log; then
  echo "The server could not bind to fd00::1 - start the Contiki client first."
  kill $PID 2>/dev/null
  exit 1
fi
echo "EDHOC server [fd00::1]:5686  log: logs/server.log (tail -f it to watch)"
echo "Waiting (Ctrl-C stops it and writes results/)..."
wait
