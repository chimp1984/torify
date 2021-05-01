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

import java.util.concurrent.CountDownLatch;

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

    public interface Listener {
        void onComplete(OnionAddress onionAddress);

        void onFault(Exception exception);

    }

    private final Torify torify;
    private final Object lock = new Object();
    @Nullable
    private OnionAddress onionAddress;

    public TorServerSocket(Torify torify) throws IOException {
        this.torify = torify;
    }

    public void bind(int hiddenServicePort, Listener listener) {
        bind(hiddenServicePort, hiddenServicePort, new File(torify.getTorDir(), HS_DIR), listener);
    }

    public void bind(int hiddenServicePort, int localPort, Listener listener) {
        bind(hiddenServicePort, localPort, new File(torify.getTorDir(), HS_DIR), listener);
    }

    public void bind(int hiddenServicePort, int localPort, File hsDir, Listener listener) {
        new Thread(() -> {
            Thread.currentThread().setName("TorServerSocket.bind");
            try {
                blockingBind(hiddenServicePort, localPort, hsDir);
                listener.onComplete(onionAddress);
            } catch (IOException | InterruptedException e) {
                listener.onFault(e);
            }
        }).start();
    }

    public void blockingBind(int hiddenServicePort, int localPort, File hsDir) throws IOException, InterruptedException {
        log.debug("Start bind TorServerSocket");
        long ts = System.currentTimeMillis();

        File hostNameFile = new File(hsDir.getCanonicalPath(), HOSTNAME);
        File privKeyFile = new File(hsDir.getCanonicalPath(), PRIV_KEY);
        FileUtil.makeDirs(hsDir);

        TorControlConnection torControlConnection = torify.getTorControlConnection();
        TorControlConnection.CreateHiddenServiceResult result;
        if (privKeyFile.exists()) {
            String privateKey = FileUtil.readFromFile(privKeyFile);
            result = torControlConnection.createHiddenService(hiddenServicePort, localPort, privateKey);
        } else {
            result = torControlConnection.createHiddenService(hiddenServicePort, localPort);
        }

        if (!hostNameFile.exists()) {
            FileUtil.makeFile(hostNameFile);
        }
        String serviceId = result.serviceID;

        synchronized (lock) {
            onionAddress = new OnionAddress(serviceId + ".onion", hiddenServicePort);
        }

        FileUtil.writeToFile(onionAddress.getHost(), hostNameFile);

        if (!privKeyFile.exists()) {
            FileUtil.makeFile(privKeyFile);
        }
        FileUtil.writeToFile(result.privateKey, privKeyFile);

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
}
