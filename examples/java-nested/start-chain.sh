#!/bin/sh
# Start the Java server and a chain of 1-3 OSCORE-capable proxies.
#
# Run inside the contiker container, from examples/java-nested, AFTER the
# client is running (it creates fd00::1 on tun0):
#   sh start-chain.sh 2        # server + proxies on 5685 (AA) and 5695 (BB)
# Stop everything with Ctrl-C.
#
# Layers on the client = proxies + 1, so 2 proxies = NUM_LAYERS=3.
N=${1:-1}
IP=${IP:-fd00::1}
CLIENT_IP=${CLIENT_IP:-fd00::302:304:506:708}
cd "$(dirname "$0")"

if [ ! -f classes/org/eclipse/californium/oscore/capable/ChainProxy.class ]; then
  echo "Compiling ChainProxy against OscoreCapableProxy.jar..."
  mkdir -p classes
  javac -nowarn -cp OscoreCapableProxy.jar -d classes ChainProxy.java || exit 1
fi

mkdir -p logs
PIDS=""
trap 'kill $PIDS 2>/dev/null; echo stopped; exit 0' INT TERM

java -jar OscoreCapableServer.jar --serverIP $IP --serverPort 5675 \
     --proxyIP $IP --proxyPort 5685 --clientIP $CLIENT_IP > logs/server.log 2>&1 &
PIDS="$PIDS $!"
echo "server  [$IP]:5675   log: logs/server.log"

i=1
for spec in 5685:AA 5695:BB 5705:CC; do
  [ $i -gt $N ] && break
  port=${spec%:*}; id=${spec#*:}
  java -cp classes:OscoreCapableProxy.jar org.eclipse.californium.oscore.capable.ChainProxy \
       --proxyIP $IP --proxyPort $port --id $id > logs/proxy$i.log 2>&1 &
  PIDS="$PIDS $!"
  echo "proxy $i [$IP]:$port  ID $id  log: logs/proxy$i.log"
  i=$((i+1))
done

echo "Client must be built with NUM_LAYERS=$((N+1)). Waiting (Ctrl-C stops all)..."
wait
