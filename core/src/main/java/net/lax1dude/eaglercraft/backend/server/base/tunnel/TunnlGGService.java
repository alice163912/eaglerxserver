/*
 * EaglerXServer tunnl.gg integration.
 *
 * This file is part of the EaglerXServer fork.
 */
package net.lax1dude.eaglercraft.backend.server.base.tunnel;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;

import net.lax1dude.eaglercraft.backend.server.adapter.IPlatformLogger;

/**
 * Opens a persistent SSH reverse tunnel to tunnl.gg without requiring an
 * operating-system SSH executable. A generated RSA-3072 identity is stored in
 * the plugin data folder and reused to preserve the stable public URL.
 */
public final class TunnlGGService implements AutoCloseable {

    private static final String SSH_HOST = "proxy.tunnl.gg";
    private static final int SSH_PORT = 22;
    private static final String SSH_USER = "stable";
    private static final String EXPECTED_HOST_FINGERPRINT =
            "SHA256:5uQ6VobmUpY4wyMmm5jnAwFtt3aX06WYDDM4ER+2WUw";

    private static final long CONNECT_TIMEOUT_MILLIS = 15_000L;
    private static final long RECONNECT_DELAY_MILLIS = 10_000L;
    private static final Pattern URL_PATTERN =
            Pattern.compile("\\\"url\\\"\\s*:\\s*\\\"(https://[^\\\"]+)\\\"");
    private static final Pattern TUNNEL_EVENT_PATTERN = Pattern.compile("\\\"event\\\"\\s*:\\s*\\\"tunnel\\\"");
    private static final Pattern NOTICE_EVENT_PATTERN = Pattern.compile("\\\"event\\\"\\s*:\\s*\\\"notice\\\"");
    private static final Pattern WARNING_PATTERN =
            Pattern.compile("\\\"warning\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    public static final class Config {
        public final boolean enabled;
        public final String listenerName;

        private Config(boolean enabled, String listenerName) {
            this.enabled = enabled;
            this.listenerName = listenerName;
        }
    }

    private final IPlatformLogger logger;
    private final File dataFolder;
    private final String targetHost;
    private final int targetPort;
    private final String listenerName;

    private volatile boolean running;
    private volatile Thread worker;
    private volatile SshClient activeClient;
    private volatile ClientSession activeSession;
    private volatile ClientChannel activeChannel;

    public static Config loadConfig(File dataFolder, IPlatformLogger logger) throws IOException {
        if (!dataFolder.exists() && !dataFolder.mkdirs()) {
            throw new IOException("Could not create plugin data folder: " + dataFolder);
        }

        File configFile = new File(dataFolder, "tunnl.properties");
        Properties properties = new Properties();

        if (configFile.isFile()) {
            try (var input = Files.newInputStream(configFile.toPath())) {
                properties.load(input);
            }
        } else {
            properties.setProperty("enabled", "true");
            properties.setProperty("listener", "default");
            try (var output = Files.newOutputStream(configFile.toPath())) {
                properties.store(output,
                        "tunnl.gg integration. This exposes your Eaglercraft listener publicly.");
            }
            logger.info("Created tunnl.gg configuration: " + configFile.getAbsolutePath());
        }

        boolean enabled = Boolean.parseBoolean(properties.getProperty("enabled", "true").trim());
        String listener = properties.getProperty("listener", "default").trim();
        if (listener.isEmpty()) {
            listener = "default";
        }

        return new Config(enabled, listener);
    }

    public TunnlGGService(IPlatformLogger logger, File dataFolder, SocketAddress listenerAddress,
            String listenerName) throws IOException {
        this.logger = logger;
        this.dataFolder = dataFolder;

        if (!(listenerAddress instanceof InetSocketAddress)) {
            throw new IOException("tunnl.gg requires a TCP listener; the selected listener is not an IP socket.");
        }

        InetSocketAddress address = (InetSocketAddress) listenerAddress;
        if (address.isUnresolved()) {
            throw new IOException("The selected EaglerXServer listener address could not be resolved.");
        }

        String host;
        if (address.getAddress().isAnyLocalAddress()) {
            host = address.getAddress() instanceof Inet6Address ? "::1" : "127.0.0.1";
        } else {
            host = address.getAddress().getHostAddress();
        }

        this.targetHost = host;
        this.targetPort = address.getPort();
        this.listenerName = listenerName == null ? "default" : listenerName;
    }

    public synchronized void start() {
        if (running) {
            return;
        }

        running = true;
        worker = new Thread(this::runReconnectLoop, "EaglerXServer-tunnl-gg");
        worker.setDaemon(true);
        worker.start();
    }

    private void runReconnectLoop() {
        while (running) {
            try {
                runTunnelSession();
                if (running) {
                    logger.warn("tunnl.gg connection ended. Reconnecting in 10 seconds...");
                }
            } catch (Exception ex) {
                if (running) {
                    logger.warn("Could not connect to tunnl.gg: " + safeMessage(ex)
                            + ". Retrying in 10 seconds.");
                }
            } finally {
                closeActiveConnection();
            }

            if (running) {
                try {
                    Thread.sleep(RECONNECT_DELAY_MILLIS);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        logger.info("tunnl.gg tunnel worker stopped.");
    }

    private void runTunnelSession() throws Exception {
        KeyPair identity = loadOrCreateIdentity();

        SshClient client = SshClient.setUpDefaultClient();
        activeClient = client;

        client.setServerKeyVerifier((session, remoteAddress, serverKey) ->
                EXPECTED_HOST_FINGERPRINT.equals(KeyUtils.getFingerPrint(serverKey)));
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        CoreModuleProperties.HEARTBEAT_INTERVAL.set(client, Duration.ofSeconds(30));
        CoreModuleProperties.HEARTBEAT_REQUEST.set(client, "keepalive@openssh.com");
        client.start();

        ClientSession session = client.connect(SSH_USER, SSH_HOST, SSH_PORT)
                .verify(CONNECT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
                .getSession();
        activeSession = session;

        session.addPublicKeyIdentity(identity);
        session.auth().verify(CONNECT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);

        SshdSocketAddress remote = new SshdSocketAddress("localhost", 80);
        SshdSocketAddress local = new SshdSocketAddress(targetHost, targetPort);
        session.startRemotePortForwarding(remote, local);

        logger.info("Connected to tunnl.gg. Publishing listener '" + listenerName + "' ("
                + targetHost + ":" + targetPort + ")...");

        ClientChannel channel = session.createExecChannel("output=json");
        activeChannel = channel;
        channel.setOut(new TunnelOutputStream(false));
        channel.setErr(new TunnelOutputStream(true));
        channel.open().verify(CONNECT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);

        channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), 0L);
    }

    private KeyPair loadOrCreateIdentity() throws Exception {
        File identityFolder = new File(dataFolder, "tunnl-gg");
        if (!identityFolder.exists() && !identityFolder.mkdirs()) {
            throw new IOException("Could not create tunnl.gg identity folder.");
        }

        Path privateKeyFile = new File(identityFolder, "identity.pk8").toPath();
        Path publicKeyFile = new File(identityFolder, "identity.x509").toPath();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        if (Files.isRegularFile(privateKeyFile) && Files.isRegularFile(publicKeyFile)) {
            byte[] privateBytes = Files.readAllBytes(privateKeyFile);
            byte[] publicBytes = Files.readAllBytes(publicKeyFile);
            return new KeyPair(
                    keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes)),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes)));
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        KeyPair pair = generator.generateKeyPair();
        Files.write(privateKeyFile, pair.getPrivate().getEncoded());
        Files.write(publicKeyFile, pair.getPublic().getEncoded());
        restrictPrivateKeyPermissions(privateKeyFile);

        logger.info("Generated a private SSH identity for tunnl.gg. It is stored in "
                + privateKeyFile.toAbsolutePath() + " and will be reused.");
        return pair;
    }

    private static void restrictPrivateKeyPermissions(Path privateKeyFile) {
        try {
            Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(privateKeyFile, permissions);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and filesystems without POSIX permissions are supported.
        }
    }

    private void closeActiveConnection() {
        ClientChannel channel = activeChannel;
        activeChannel = null;
        if (channel != null) {
            try {
                channel.close(true);
            } catch (Exception ignored) {
            }
        }

        ClientSession session = activeSession;
        activeSession = null;
        if (session != null) {
            try {
                session.close(true);
            } catch (Exception ignored) {
            }
        }

        SshClient client = activeClient;
        activeClient = null;
        if (client != null) {
            try {
                client.stop();
            } catch (Exception ignored) {
            }
        }
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank()
                ? throwable.getClass().getSimpleName() : message;
    }

    @Override
    public synchronized void close() {
        running = false;
        Thread thread = worker;
        worker = null;

        closeActiveConnection();

        if (thread != null) {
            thread.interrupt();
            try {
                thread.join(3_000L);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private final class TunnelOutputStream extends OutputStream {
        private final boolean errorStream;
        private final ByteArrayOutputStream line = new ByteArrayOutputStream();

        private TunnelOutputStream(boolean errorStream) {
            this.errorStream = errorStream;
        }

        @Override
        public synchronized void write(int value) {
            if (value == '\n') {
                processLine(line.toString(StandardCharsets.UTF_8));
                line.reset();
            } else if (value != '\r') {
                line.write(value);
            }
        }

        @Override
        public synchronized void write(byte[] bytes, int offset, int length) {
            for (int i = offset; i < offset + length; i++) {
                write(bytes[i] & 0xff);
            }
        }

        @Override
        public synchronized void flush() {
            if (line.size() > 0) {
                processLine(line.toString(StandardCharsets.UTF_8));
                line.reset();
            }
        }

        private void processLine(String value) {
            String trimmed = value.trim();
            if (trimmed.isEmpty()) {
                return;
            }

            if (errorStream) {
                logger.warn("tunnl.gg: " + trimmed);
                return;
            }

            if (TUNNEL_EVENT_PATTERN.matcher(trimmed).find()) {

                Matcher urlMatcher = URL_PATTERN.matcher(trimmed);
                if (urlMatcher.find()) {
                    String httpsUrl = urlMatcher.group(1);
                    String websocketUrl = "wss://" + httpsUrl.substring("https://".length());
                    logger.info("tunnl.gg is ready! Browser URL: " + httpsUrl
                            + " | Eaglercraft WebSocket address: " + websocketUrl);
                } else {
                    logger.warn("tunnl.gg reported that the tunnel started, but did not provide a URL: " + trimmed);
                }

                Matcher warningMatcher = WARNING_PATTERN.matcher(trimmed);
                if (warningMatcher.find()) {
                    logger.warn("tunnl.gg warning: " + warningMatcher.group(1));
                }
            } else if (NOTICE_EVENT_PATTERN.matcher(trimmed).find()) {

                logger.info("tunnl.gg: " + trimmed);
            }
        }
    }
}
