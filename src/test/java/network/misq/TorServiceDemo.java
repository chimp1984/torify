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

package network.misq;

import com.runjva.sourceforge.jsocks.protocol.SocksSocket;

import javax.net.SocketFactory;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import lombok.extern.slf4j.Slf4j;



import misq.torify.OnionAddress;
import misq.torify.TorServerSocket;
import misq.torify.TorService;

@Slf4j
public class TorServiceDemo {
    public static void main(String[] args) {
        String torDirPath = "/Users/dev/Library/Application Support/misq_TorNew/TorifyDemo";
        //  useBlockingAPI(torDirPath);
        useNonBlockingAPI(torDirPath);
       /* while (true) {
        }*/
    }

    private static void useBlockingAPI(String torDirPath) throws IOException, InterruptedException {
        TorService torService = new TorService(torDirPath);
        torService.blockingStart();
        TorServerSocket torServerSocket = startServerBlocking(torService);
        OnionAddress onionAddress = torServerSocket.getOnionAddress();
        sendViaSocketFactory(torService, onionAddress);
        sendViaProxy(torService, onionAddress);
        sendViaSocket(torService, onionAddress);
        sendViaSocksSocket(torService, onionAddress);
    }

    private static void useNonBlockingAPI(String torDirPath) {
        TorService torService = new TorService(torDirPath);
        torService.start(new TorService.Listener() {
            @Override
            public void onComplete() {
                startServerNonBlocking(torService, onionAddress -> {
                    sendViaSocketFactory(torService, onionAddress);
                    sendViaProxy(torService, onionAddress);
                    sendViaSocket(torService, onionAddress);
                    sendViaSocksSocket(torService, onionAddress);
                });
            }

            @Override
            public void onFault(Exception exception) {
                log.error(exception.toString());
            }
        });
    }

    // Server
    private static TorServerSocket startServerBlocking(TorService torService) {
        try {
            TorServerSocket torServerSocket = new TorServerSocket(torService);
            // blocking version
            torServerSocket.blockingBind(4000, 9999, new File(torService.getTorDir(), "hiddenservice_2"));
            runServer(torServerSocket);
            return torServerSocket;
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static void startServerNonBlocking(TorService torService, Consumer<OnionAddress> resultHandler) {
        try {
            TorServerSocket torServerSocket = new TorServerSocket(torService);
            torServerSocket.bind(3000, new TorServerSocket.Listener() {
                @Override
                public void onComplete(OnionAddress onionAddress) {
                    runServer(torServerSocket);
                    resultHandler.accept(torServerSocket.getOnionAddress());
                }

                @Override
                public void onFault(Exception exception) {
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void runServer(TorServerSocket torServerSocket) {
        new Thread(() -> {
            Thread.currentThread().setName("Server");
            while (true) {
                try {
                    log.info("Start listening for new connections on {}", torServerSocket.getOnionAddress());
                    Socket clientSocket = torServerSocket.accept();
                    clientSocket.setSoTimeout((int) TimeUnit.MINUTES.toMillis(1));
                    createInboundConnection(clientSocket);
                } catch (IOException e) {
                    e.printStackTrace();
                    try {
                        torServerSocket.close();
                    } catch (IOException ignore) {
                    }
                }
            }
        }).start();
    }

    private static void createInboundConnection(Socket clientSocket) {
        log.info("New client connection accepted");
        new Thread(() -> {
            Thread.currentThread().setName("Read at inbound connection");
            try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
                 ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream())) {
                objectOutputStream.flush();
                listenOnInputStream(clientSocket, objectInputStream, "inbound connection");
            } catch (IOException e) {
                log.error("Close clientSocket objectOutputStream " + e.toString());
                try {
                    clientSocket.close();
                } catch (IOException ignore) {
                }
            }
        }).start();
    }

    private static void listenOnInputStream(Socket socket, ObjectInputStream objectInputStream, String info) {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Object object = objectInputStream.readObject();
                log.info("Received at {} {}", info, object);
            }
        } catch (IOException | ClassNotFoundException e) {
            log.error("Close socket at {}. {}", info, e.toString());
            try {
                socket.close();
            } catch (IOException ignore) {
            }
        }
    }

    // Outbound connection
    private static void sendViaSocket(TorService torService, OnionAddress onionAddress) {
        try {
            Socket socket = torService.getSocket("test_stream_id");
            socket.connect(new InetSocketAddress(onionAddress.getHost(), onionAddress.getPort()));
            sendOnOutboundConnection(socket, "test via Socket");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendViaSocksSocket(TorService torService, OnionAddress onionAddress) {
        try {
            SocksSocket socket = torService.getSocksSocket(onionAddress.getHost(), onionAddress.getPort(), "test_stream_id");
            sendOnOutboundConnection(socket, "test via SocksSocket");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendViaSocketFactory(TorService torService, OnionAddress onionAddress) {
        try {
            SocketFactory socketFactory = torService.getSocketFactory("test_stream_id");
            Socket socket = socketFactory.createSocket(onionAddress.getHost(), onionAddress.getPort());
            sendOnOutboundConnection(socket, "test via SocketFactory");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendViaProxy(TorService torService, OnionAddress onionAddress) {
        try {
            Proxy proxy = torService.getProxy("test_stream_id");
            Socket socket = new Socket(proxy);
            socket.connect(new InetSocketAddress(onionAddress.getHost(), onionAddress.getPort()));
            sendOnOutboundConnection(socket, "test via Proxy");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendOnOutboundConnection(Socket socket, String msg) {
        log.info("sendViaOutboundConnection {}", msg);
        new Thread(() -> {
            try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream())) {
                objectOutputStream.writeObject(msg);
                objectOutputStream.flush();
                listenOnInputStream(socket, objectInputStream, "outbound connection");
            } catch (IOException e) {
                log.error("Close socket. {} {}", msg, e.toString());
                try {
                    socket.close();
                } catch (IOException ignore) {
                }
            }
        }).start();
    }
}
