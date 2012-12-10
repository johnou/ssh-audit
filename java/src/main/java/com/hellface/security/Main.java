package com.hellface.security;

import com.trilead.ssh2.Connection;
import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.transport.ClientServerHello;
import org.apache.commons.net.util.SubnetUtils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * @author Johno Crawford (johno@hellface.com)
 */
public class Main {

    private final Credentials[] SSH_CREDENTIALS = new Credentials[]{
            new Credentials("root", "temppwd"),
    };

    private AtomicInteger success = new AtomicInteger();
    private AtomicInteger failed = new AtomicInteger();
    private AtomicInteger password = new AtomicInteger();

    private static final int TIMEOUT = 6000;

    private static final ExecutorService executor = Executors.newFixedThreadPool(10);

    public Main(String path) throws InterruptedException {
        Set<String> hosts = new LinkedHashSet<String>();
        BufferedReader bufferedReader = null;
        try {
            bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    hosts.add(line.trim());
                }
            }
        } catch (IOException e) {
            System.err.println(e.toString());
            System.exit(-1);
        } finally {
            try {
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            } catch (IOException ignore) {
            }
        }
        long start = System.currentTimeMillis();
        for (Credentials credentials : SSH_CREDENTIALS) {
            for (String host : hosts) {
                // CIDR
                if (host.contains("/")) {
                    SubnetUtils subnetUtils = new SubnetUtils(host);
                    String[] addresses = subnetUtils.getInfo().getAllAddresses();
                    for (String address : addresses) {
                        queue(credentials, address);
                    }
                } else {
                    queue(credentials, host);
                }
            }
        }
        executor.shutdown();
        executor.awaitTermination(Integer.MAX_VALUE, TimeUnit.SECONDS);
        System.out.printf("Audit complete in: %d ms.%n", System.currentTimeMillis() - start);
        System.out.println("Hosts running SSH: " + success.get());
        System.out.println("Hosts blocking or not running SSH: " + failed.get());
        System.out.println("Hosts running SSH with default credentials: " + password.get());
    }

    private void queue(Credentials credentials, String host) {
        String hostname;
        int port = 22;
        if (host.contains(":")) {
            String[] parts = host.split(Pattern.quote(":"));
            hostname = parts[0];
            try {
                port = Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignore) {
            }
        } else {
            hostname = host;
        }
        queue(credentials, hostname, port);
    }

    private void queue(final Credentials credentials, final String hostname, final int port) {
        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                Connection connection = null;
                try {
                    connection = new Connection(hostname, port);
                    connection.setTCPNoDelay(true);
                    connection.connect(new AuditVerifier(), TIMEOUT, TIMEOUT);
                    success.getAndIncrement();
                    boolean authenticated = connection.authenticateWithPassword(credentials.username, credentials.password);
                    if (authenticated) {
                        password.getAndIncrement();
                        System.out.println(hostname + " default login credentials [" + credentials.username + "] have not been updated!");
                    }
                } catch (IOException e) {
                    failed.getAndIncrement();
                    System.out.println(hostname + " with login [" + credentials.username + "] " + e.toString());
                } finally {
                    if (connection != null) {
                        try {
                            ClientServerHello version = connection.getVersionInfo();
                            if (version != null) {
                                System.out.println(hostname + " running " + (new String(version.getServerString())));
                            }
                        } catch (IOException ignore) {
                        } catch (IllegalStateException ignore) {
                        }
                        connection.close();
                    }
                }
            }
        };
        executor.execute(runnable);
    }

    private static class Credentials {
        private String username;
        private String password;

        private Credentials(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    private static class AuditVerifier implements ServerHostKeyVerifier {
        @Override
        public boolean verifyServerHostKey(String s, int i, String s1, byte[] bytes) {
            return true;
        }
    }

    public static void main(String[] args) throws InterruptedException {
        if (args.length < 1) {
            System.err.println("Usage: java -jar -Xss256k -Xms32m -Xmx32m SSHAudit.jar <path to host list>");
            System.exit(-1);
        }
        new Main(args[0]);
    }
}
