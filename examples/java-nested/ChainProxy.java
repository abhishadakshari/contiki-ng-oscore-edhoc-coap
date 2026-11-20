/*******************************************************************************
 * Configurable OSCORE-capable forward proxy for chaining several proxies.
 *
 * Based on OSCoreCapableProxy (rikard-sics/californium, branch
 * oscore_capable_proxies). The proxy logic is unchanged; what is new is that
 * the OSCORE context it shares with the client and the address it listens on
 * are set on the command line, so several proxies can run side by side, each
 * removing its own layer (layer limit 1) and forwarding by the Proxy-Uri it
 * finds inside that layer.
 *
 * Build (in examples/java-nested):
 *   javac -cp OscoreCapableProxy.jar -d classes ChainProxy.java
 * Run:
 *   java -cp classes:OscoreCapableProxy.jar org.eclipse.californium.oscore.capable.ChainProxy \
 *        --proxyIP fd00::1 --proxyPort 5695 --id BB
 ******************************************************************************/
package org.eclipse.californium.oscore.capable;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.TrackerMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.ClientSingleEndpoint;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;

public class ChainProxy {

	private static final File CONFIG_FILE = new File("CaliforniumProxy3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Example Proxy";

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
		Proxy2Config.register();
	}

	/* Same defaults as OSCoreCapableProxy. */
	private static final DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 20000);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, 8192);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, 1024);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, 1024);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, 10, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTPS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, 8192);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, 8192);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
		}
	};

	/* Test keying material shared with the client (RFC 8613 Appendix C.1.1). */
	private final static byte[] MASTER_SECRET = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
			0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] MASTER_SALT = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static AlgorithmID ALG = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID KDF = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	/* Command-line settings. Defaults reproduce the original proxy. */
	private static String proxyIP = "127.0.0.1";
	private static int proxyPort = 5685;
	private static byte[] sid = { (byte) 0xAA };   /* this proxy's Sender ID */
	private static byte[] rid = { (byte) 0xAA };   /* the client's Sender ID */
	private static byte[] idContext = { (byte) 0xAA };
	private static int layerLimit = 1;             /* layers this proxy removes */

	private final CoapServer coapProxyServer;

	public ChainProxy(Configuration config) throws IOException, OSException {
		HashMapCtxDB db = new HashMapCtxDB(true, layerLimit);

		/* The context shared with the client for this proxy's layer. It is
		 * found by the kid in the incoming OSCORE option, so no URI is needed. */
		OSCoreCtx ctxToClient = new OSCoreCtx(MASTER_SECRET, true, ALG, sid, rid, KDF, 32, MASTER_SALT, idContext,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(ctxToClient);
		OSCoreCoapStackFactory.useAsDefault(db);

		/* Outgoing side: forwards to the next hop named by the Proxy-Uri. */
		Configuration outgoingConfig = new Configuration(config);
		outgoingConfig.set(CoapConfig.MID_TRACKER, TrackerMode.NULL);
		ClientEndpoints proxyToNextHop = new ClientSingleEndpoint(
				CoapEndpoint.builder().setConfiguration(outgoingConfig).build());

		Coap2CoapTranslator translator = new Coap2CoapTranslator();
		ProxyCoapResource coap2coap = new ProxyCoapClientResource("coap2coap", false, false, translator,
				proxyToNextHop);

		/* Incoming side: where the previous hop sends to. */
		CoapEndpoint incoming = CoapEndpoint.builder()
				.setInetSocketAddress(new InetSocketAddress(proxyIP, proxyPort)).build();
		coapProxyServer = new CoapServer(config);
		coapProxyServer.addEndpoint(incoming);

		ForwardProxyMessageDeliverer deliverer = new ForwardProxyMessageDeliverer(coapProxyServer.getRoot(),
				translator, config);
		deliverer.addProxyCoapResources(coap2coap);
		deliverer.addExposedServiceAddresses(new InetSocketAddress(proxyIP, proxyPort));
		coapProxyServer.setMessageDeliverer(deliverer);
		coapProxyServer.add(coap2coap);
		coapProxyServer.start();
		deliverer.startLocalAddressResolver();
	}

	public static void main(String[] args) throws IOException, OSException {
		parseArguments(args);
		System.out.println("=================================");
		System.out.println("Chain proxy listening on [" + proxyIP + "]:" + proxyPort);
		System.out.println("  Sender ID   = " + hex(sid));
		System.out.println("  Recipient ID= " + hex(rid) + " (the client's Sender ID for this layer)");
		System.out.println("  ID Context  = " + hex(idContext));
		System.out.println("  Layer limit = " + layerLimit);
		System.out.println("=================================");

		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		new ChainProxy(config);
		for (;;) {
			try {
				Thread.sleep(15000);
			} catch (InterruptedException e) {
				return;
			}
		}
	}

	private static void usage() {
		System.out.println("Usage: ChainProxy [options]");
		System.out.println("  --proxyIP <ip>       address to listen on (default 127.0.0.1)");
		System.out.println("  --proxyPort <port>   port to listen on (default 5685)");
		System.out.println("  --id <hex>           sets Sender ID, Recipient ID and ID Context together");
		System.out.println("  --sid <hex>          this proxy's Sender ID");
		System.out.println("  --rid <hex>          the client's Sender ID for this layer");
		System.out.println("  --idctx <hex>        ID Context (use 'none' for no ID Context)");
		System.out.println("  --layerLimit <n>     layers this proxy may remove (default 1)");
		System.out.println("  --serverIP, --serverPort, --clientIP are accepted and ignored");
	}

	private static void parseArguments(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String arg = args[i];
			String value = null;
			int eq = arg.indexOf('=');
			if (arg.startsWith("--") && eq > 0) {
				value = arg.substring(eq + 1);
				arg = arg.substring(0, eq);
			}
			if (arg.equals("--help")) {
				usage();
				System.exit(0);
			}
			if (value == null) {
				if (i + 1 >= args.length) {
					System.err.println("Missing value for " + arg);
					System.exit(1);
				}
				value = args[++i];
			}
			switch (arg) {
			case "--proxyIP":
				proxyIP = value;
				break;
			case "--proxyPort":
				proxyPort = Integer.parseInt(value);
				break;
			case "--id":
				sid = parseHex(value);
				rid = parseHex(value);
				idContext = parseHex(value);
				break;
			case "--sid":
				sid = parseHex(value);
				break;
			case "--rid":
				rid = parseHex(value);
				break;
			case "--idctx":
				idContext = value.equalsIgnoreCase("none") ? null : parseHex(value);
				break;
			case "--layerLimit":
				layerLimit = Integer.parseInt(value);
				break;
			case "--serverIP":
			case "--serverPort":
			case "--clientIP":
				break; /* kept so the old start scripts still work */
			default:
				System.err.println("Unknown argument: " + arg);
				usage();
				System.exit(1);
			}
		}
	}

	private static byte[] parseHex(String s) {
		s = s.replaceFirst("^0[xX]", "");
		if (s.length() == 0 || s.length() % 2 != 0) {
			throw new IllegalArgumentException("Hex value needs an even number of digits: " + s);
		}
		byte[] out = new byte[s.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return out;
	}

	private static String hex(byte[] b) {
		if (b == null) {
			return "none";
		}
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02X", x));
		}
		return sb.toString();
	}
}
