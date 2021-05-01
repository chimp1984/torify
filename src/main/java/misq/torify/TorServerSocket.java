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

import lombok.extern.slf4j.Slf4j;
import net.freehaven.tor.control.TorControlConnection;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.concurrent.CountDownLatch;

import static misq.torify.Constants.*;

@Slf4j
public class TorServerSocket extends ServerSocket {
    public interface Listener {
        void onComplete(OnionAddress onionAddress);

        void onFault(Exception exception);

    }

    private final TorService torService;
    private final Object lock = new Object();
    @Nullable
    private OnionAddress onionAddress;

    public TorServerSocket(TorService torService) throws IOException {
        this.torService = torService;
    }

    public void bind(int hiddenServicePort, Listener listener) {
        bind(hiddenServicePort, hiddenServicePort, new File(torService.getTorDir(), HS_DIR), listener);
    }

    public void bind(int hiddenServicePort, int localPort, Listener listener) {
        bind(hiddenServicePort, localPort, new File(torService.getTorDir(), HS_DIR), listener);
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

        TorControlConnection torControlConnection = torService.getTorControlConnection();
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
        torService.getEventHandler().putHiddenServiceReadyListener(serviceId, () -> {
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
            torService.getEventHandler().removeHiddenServiceReadyListener(onionAddress.getServiceId());
            torService.getTorControlConnection().destroyHiddenService(onionAddress.getServiceId());
        }
    }

    @Nullable
    public OnionAddress getOnionAddress() {
        return onionAddress;
    }
}
