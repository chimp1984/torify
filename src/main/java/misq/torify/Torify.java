/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package misq.torify;

import com.runjva.sourceforge.jsocks.protocol.Authentication;
import com.runjva.sourceforge.jsocks.protocol.Socks5Proxy;
import com.runjva.sourceforge.jsocks.protocol.SocksSocket;

import com.google.common.util.concurrent.MoreExecutors;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.net.SocketFactory;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;

import java.math.BigInteger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import java.lang.management.ManagementFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;

public class Torify {
    private static final Logger log = LoggerFactory.getLogger(Torify.class);
    public final static String TOR_SERVICE_VERSION = "0.1.0";

    private final List<String> bridgeConfig = new ArrayList<>();
    private final String torDirPath;
    private final File torDir;
    private final File dotTorDir;
    private final File versionFile;
    private final File pidFile;
    private final File geoIPFile;
    private final File geoIPv6File;
    private final File torrcFile;
    private final File cookieFile;
    private final OsType osType;
    private final TorController torController;

    private volatile boolean shutdownRequested;
    @Nullable
    private ExecutorService startupExecutor;
    private int proxyPort;

    public Torify(String torDirPath) {
        this.torDirPath = torDirPath;

        torDir = new File(torDirPath);
        dotTorDir = new File(torDirPath, Constants.DOT_TOR);
        versionFile = new File(torDirPath, Constants.VERSION);
        pidFile = new File(torDirPath, Constants.PID);
        geoIPFile = new File(torDirPath, Constants.GEO_IP);
        geoIPv6File = new File(torDirPath, Constants.GEO_IPV_6);
        torrcFile = new File(torDirPath, Constants.TORRC);
        cookieFile = new File(dotTorDir.getAbsoluteFile(), Constants.COOKIE);
        torController = new TorController(cookieFile);
        osType = OsType.detectOs();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Thread.currentThread().setName("Torify.shutdownHook");
            shutdown();
        }));
    }

    public void shutdown() {
        shutdownRequested = true;
        log.info("Start shutdown Tor");

        if (startupExecutor != null) {
            MoreExecutors.shutdownAndAwaitTermination(startupExecutor, 100, TimeUnit.MILLISECONDS);
            startupExecutor = null;
        }
        torController.shutdown();
        log.info("Shutdown Tor completed");
    }

    public CompletableFuture<TorController> startAsync() {
        return startAsync(getStartupExecutor());
    }

    public CompletableFuture<TorController> startAsync(Executor executor) {
        CompletableFuture<TorController> future = new CompletableFuture<>();
        checkArgument(!shutdownRequested, "shutdown already requested");
        executor.execute(() -> {
            try {
                TorController torController = start();
                future.complete(torController);
            } catch (IOException | InterruptedException e) {
                deleteVersionFile();
                future.completeExceptionally(e);
            }
        });
        return future;
    }

    // Blocking start
    public TorController start() throws IOException, InterruptedException {
        checkArgument(!shutdownRequested, "shutdown already requested");
        long ts = System.currentTimeMillis();
        maybeCleanupCookieFile();
        if (!isUpToDate()) {
            installFiles();
        }

        if (!bridgeConfig.isEmpty()) {
            addBridgesToTorrcFile(bridgeConfig);
        }

        Process torProcess = startTorProcess();
        log.info("Tor process started");


        int controlPort = waitForControlPort(torProcess);
        terminateProcessBuilder(torProcess);

        waitForCookieInitialized();
        log.info("Cookie initialized");

        torController.startControlConnection(controlPort);
        proxyPort = torController.getProxyPort();

        log.info("Bootstrap complete");
        log.info(">>>>>> Starting Tor took {} ms", System.currentTimeMillis() - ts);
        return torController;
    }

    public SocksSocket getSocksSocket(String remoteHost, int remotePort, @Nullable String streamId) throws IOException {
        checkArgument(!shutdownRequested, "shutdown already requested");
        Socks5Proxy socks5Proxy = getSocks5Proxy(streamId);
        SocksSocket socksSocket = new SocksSocket(socks5Proxy, remoteHost, remotePort);
        socksSocket.setTcpNoDelay(true);
        return socksSocket;
    }

    public Socket getSocket() throws IOException {
        return new Socket(getProxy(null));
    }

    public Socket getSocket(@Nullable String streamId) throws IOException {
        checkArgument(!shutdownRequested, "shutdown already requested");
        return new Socket(getProxy(streamId));
    }

    public Proxy getProxy(@Nullable String streamId) throws IOException {
        checkArgument(!shutdownRequested, "shutdown already requested");
        Socks5Proxy socks5Proxy = getSocks5Proxy(streamId);
        InetSocketAddress socketAddress = new InetSocketAddress(socks5Proxy.getInetAddress(), socks5Proxy.getPort());
        return new Proxy(Proxy.Type.SOCKS, socketAddress);
    }

    public SocketFactory getSocketFactory(@Nullable String streamId) throws IOException {
        checkArgument(!shutdownRequested, "shutdown already requested");
        return new TorSocketFactory(getProxy(streamId));
    }

    public Socks5Proxy getSocks5Proxy(@Nullable String streamId) throws IOException {
        checkArgument(!shutdownRequested, "shutdown already requested");
        Socks5Proxy socks5Proxy = new Socks5Proxy(Constants.LOCALHOST, proxyPort);
        socks5Proxy.resolveAddrLocally(false);
        if (streamId == null) {
            return socks5Proxy;
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digest = messageDigest.digest(streamId.getBytes());
            String asBase26 = new BigInteger(digest).toString(26);
            byte[] hash = asBase26.getBytes();
            // Authentication method ID 2 is User/Password
            socks5Proxy.setAuthenticationMethod(2,
                    new Authentication() {
                        @Override
                        public Object[] doSocksAuthentication(int i, Socket socket) throws IOException {
                            // Must not close streams here, as otherwise we get a socket closed
                            // exception at SocksSocket
                            OutputStream outputStream = socket.getOutputStream();
                            outputStream.write(new byte[]{(byte) 1, (byte) hash.length});
                            outputStream.write(hash);
                            outputStream.write(new byte[]{(byte) 1, (byte) 0});
                            outputStream.flush();

                            byte[] status = new byte[2];
                            InputStream inputStream = socket.getInputStream();
                            if (inputStream.read(status) == -1) {
                                throw new IOException("Did not get data");
                            }
                            if (status[1] != (byte) 0) {
                                throw new IOException("Authentication error: " + status[1]);
                            }
                            return new Object[]{inputStream, outputStream};
                        }
                    });
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return socks5Proxy;
    }

 /*   public TorController getTorController() {
        return torController;
    }*/


    ////////////////////////////////////////////////////////////////////////////////////////////////////
    // Private
    ////////////////////////////////////////////////////////////////////////////////////////////////////


    private void maybeCleanupCookieFile() throws IOException {
        File cookieFile = new File(torDirPath, Constants.DOT_TOR + File.separator + Constants.COOKIE);
        if (cookieFile.exists() && !cookieFile.delete()) {
            throw new IOException("Cannot delete old cookie file.");
        }
    }

    private boolean isUpToDate() throws IOException {
        return versionFile.exists() && TOR_SERVICE_VERSION.equals(Utils.readFromFile(versionFile));
    }

    private void installFiles() throws IOException {
        try {
            Utils.makeDirs(torDir);
            Utils.makeDirs(dotTorDir);

            Utils.makeFile(versionFile);

            Utils.resourceToFile(geoIPFile);
            Utils.resourceToFile(geoIPv6File);

            installTorrcFile();

            Utils.extractBinary(torDirPath, osType);
            log.info("Tor files installed to {}", torDirPath);
            // Only if we have successfully extracted all files we write our version file which is used to
            // check if we need to call installFiles.
            Utils.writeToFile(TOR_SERVICE_VERSION, versionFile);
        } catch (Throwable e) {
            deleteVersionFile();
            throw e;
        }
    }

    private void installTorrcFile() throws IOException {
        Utils.resourceToFile(torrcFile);
        extendTorrcFile();
    }

    private void extendTorrcFile() throws IOException {
        try (FileWriter fileWriter = new FileWriter(torrcFile, true);
             BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
             PrintWriter printWriter = new PrintWriter(bufferedWriter)) {

            // Defaults are from resources
            printWriter.println("");
            Utils.appendFromResource(printWriter, "/" + Constants.TORRC_DEFAULTS);
            printWriter.println("");
            Utils.appendFromResource(printWriter, osType.getTorrcNative());

            // Update with our newly created files
            printWriter.println("");
            printWriter.println(Constants.TORRC_KEY_DATA_DIRECTORY + " " + torDir.getCanonicalPath());
            printWriter.println(Constants.TORRC_KEY_GEOIP + " " + geoIPFile.getCanonicalPath());
            printWriter.println(Constants.TORRC_KEY_GEOIP6 + " " + geoIPv6File.getCanonicalPath());
            printWriter.println(Constants.TORRC_KEY_PID + " " + pidFile.getCanonicalPath());
            printWriter.println(Constants.TORRC_KEY_COOKIE + " " + cookieFile.getCanonicalPath());
            printWriter.println("");
        }
    }

    private void addBridgesToTorrcFile(List<String> bridgeConfig) throws IOException {
        // We overwrite old file as it might contain diff. bridges
        installTorrcFile();

        try (FileWriter fileWriter = new FileWriter(torrcFile, true);
             BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
             PrintWriter printWriter = new PrintWriter(bufferedWriter)) {
            if (!bridgeConfig.isEmpty()) {
                printWriter.println("");
                printWriter.println("UseBridges 1");
            }
            bridgeConfig.forEach(entry -> {
                printWriter.println("Bridge " + entry);
            });
        }
        log.info("Added bridges to torrc");
    }

    private void deleteVersionFile() {
        if (versionFile != null)
            versionFile.delete();
    }

    private Process startTorProcess() throws IOException {
        String processName = ManagementFactory.getRuntimeMXBean().getName();
        String ownerPid = processName.split("@")[0];
        log.debug("Owner pid {}", ownerPid);
        Utils.writeToFile(ownerPid, pidFile);

        String path = new File(torDir, osType.getBinaryName()).getAbsolutePath();
        String[] command = {path, "-f", torrcFile.getAbsolutePath(), Constants.OWNER, ownerPid};
        log.debug("command for process builder: {} {} {} {} {}",
                path, "-f", torrcFile.getAbsolutePath(), Constants.OWNER, ownerPid);
        ProcessBuilder processBuilder = new ProcessBuilder(command);

        processBuilder.directory(torDir);
        Map<String, String> environment = processBuilder.environment();
        environment.put("HOME", torDir.getAbsolutePath());
        switch (osType) {
            case LNX32:
            case LNX64:
                // TODO Taken from netlayer, but not sure if needed. Not used in Briar.
                // Not recommended to be used here: https://www.hpc.dtu.dk/?page_id=1180
                environment.put("LD_LIBRARY_PATH", torDir.getAbsolutePath());
                break;
            default:
        }

        Process process = processBuilder.start();
        log.debug("Process started. pid={} info={}", process.pid(), process.info());
        return process;
    }

    private int waitForControlPort(Process torProcess) {
        AtomicInteger controlPort = new AtomicInteger();
        try (Scanner info = new Scanner(torProcess.getInputStream());
             Scanner error = new Scanner(torProcess.getErrorStream())) {
            while (info.hasNextLine() || error.hasNextLine()) {
                if (info.hasNextLine()) {
                    String line = info.nextLine();
                    log.debug("Logs from control connection: >> {}", line);
                    if (line.contains(Constants.LOG_OF_CONTROL_PORT)) {
                        String[] split = line.split(Constants.LOG_OF_CONTROL_PORT);
                        String portString = split[1].replace(".", "");
                        controlPort.set(Integer.parseInt(portString));
                        log.info("Control connection port: {}", controlPort);
                    }
                }
                if (error.hasNextLine()) {
                    log.error(error.nextLine());
                }
            }
        }
        return controlPort.get();
    }

    private void terminateProcessBuilder(Process torProcess) throws InterruptedException, IOException {
        if (osType != OsType.WIN) {
            int result = torProcess.waitFor();
            if (torProcess.waitFor() != 0) {
                throw new IOException("Tor exited with value " + result);
            }
        }
        log.debug("Process builder terminated");
    }

    private void waitForCookieInitialized() throws InterruptedException, IOException {
        long start = System.currentTimeMillis();
        while (cookieFile.length() < 32 && !Thread.currentThread().isInterrupted()) {
            if (System.currentTimeMillis() - start > 5000) {
                throw new IOException("Auth cookie not created");
            }
            Thread.sleep(50);
        }
    }

    private ExecutorService getStartupExecutor() {
        startupExecutor = Utils.getSingleThreadExecutor("Torify.startAsync");
        return startupExecutor;
    }
}
