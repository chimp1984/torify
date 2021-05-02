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

import java.net.InetSocketAddress;
import java.net.ServerSocket;

import java.io.File;
import java.io.IOException;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import static misq.torify.Constants.HOSTNAME;
import static misq.torify.Constants.HS_DIR;
import static misq.torify.Constants.LOCALHOST;
import static misq.torify.Constants.PRIV_KEY;



import net.freehaven.tor.control.TorControlConnection;

public class TorServerSocket extends ServerSocket {
    private static final Logger log = LoggerFactory.getLogger(TorServerSocket.class);

    private final Torify torify;
    @Nullable
    private OnionAddress onionAddress;
    @Nullable
    private ExecutorService executor;

    public TorServerSocket(Torify torify) throws IOException {
        this.torify = torify;
    }


    public CompletableFuture<OnionAddress> bindAsync(int hiddenServicePort) {
        return bindAsync(hiddenServicePort, hiddenServicePort);
    }

    public CompletableFuture<OnionAddress> bindAsync(int hiddenServicePort, int localPort) {
        return bindAsync(hiddenServicePort, localPort, new File(torify.getTorDir(), HS_DIR));
    }

    public CompletableFuture<OnionAddress> bindAsync(int hiddenServicePort, int localPort, File hsDir) {
        return bindAsync(hiddenServicePort, localPort, hsDir, getExecutor());
    }

    public CompletableFuture<OnionAddress> bindAsync(int hiddenServicePort,
                                                     int localPort,
                                                     File hsDir,
                                                     @Nullable Executor executor) {
        CompletableFuture<OnionAddress> future = new CompletableFuture<>();
        if (executor == null) {
            executor = Utils.directExecutor();
        }
        executor.execute(() -> {
            Thread.currentThread().setName("TorServerSocket.bind");
            try {
                bind(hiddenServicePort, localPort, hsDir);
                future.complete(onionAddress);
            } catch (IOException | InterruptedException e) {
                future.completeExceptionally(e);
            }
        });
        return future;
    }

    // Blocking
    public void bind(int hiddenServicePort, int localPort, File hsDir) throws IOException, InterruptedException {
        log.debug("Start bind TorServerSocket");
        long ts = System.currentTimeMillis();

        File hostNameFile = new File(hsDir.getCanonicalPath(), HOSTNAME);
        File privKeyFile = new File(hsDir.getCanonicalPath(), PRIV_KEY);
        Utils.makeDirs(hsDir);

        TorControlConnection torControlConnection = torify.getTorControlConnection();
        TorControlConnection.CreateHiddenServiceResult result;
        if (privKeyFile.exists()) {
            String privateKey = Utils.readFromFile(privKeyFile);
            result = torControlConnection.createHiddenService(hiddenServicePort, localPort, privateKey);
        } else {
            result = torControlConnection.createHiddenService(hiddenServicePort, localPort);
        }

        if (!hostNameFile.exists()) {
            Utils.makeFile(hostNameFile);
        }
        String serviceId = result.serviceID;

        onionAddress = new OnionAddress(serviceId + ".onion", hiddenServicePort);
        Utils.writeToFile(onionAddress.getHost(), hostNameFile);

        if (!privKeyFile.exists()) {
            Utils.makeFile(privKeyFile);
        }
        Utils.writeToFile(result.privateKey, privKeyFile);

        log.debug("Start publishing hidden service {}", onionAddress);
        CountDownLatch latch = new CountDownLatch(1);
        torify.getEventHandler().putHiddenServiceReadyListener(serviceId, () -> {
            try {
                super.bind(new InetSocketAddress(LOCALHOST, localPort));
                log.info(">> TorServerSocket ready. Took {} ms", System.currentTimeMillis() - ts);
                latch.countDown();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        latch.await();
    }

    @Override
    public void close() throws IOException {
        super.close();

        if (onionAddress != null) {
            torify.getEventHandler().removeHiddenServiceReadyListener(onionAddress.getServiceId());
            torify.getTorControlConnection().destroyHiddenService(onionAddress.getServiceId());
        }
    }

    @Nullable
    public OnionAddress getOnionAddress() {
        return onionAddress;
    }

    private ExecutorService getExecutor() {
        executor = Utils.getSingleThreadExecutor("TorServerSocket.bindAsync");
        return executor;
    }
}
