package com.example.springdemo;

import ch.qos.logback.core.encoder.ByteArrayUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@SpringBootApplication
public class SimpleTcpProxy {
    public static void main(String[] args) throws Exception {
        CommandLineParser parser = new GnuParser();
        Options options = new Options();
        options.addOption(null, "proxyHost", true, "");
        options.addOption(null, "proxyPort", true, "");
        options.addOption(null, "targetHost", true, "");
        options.addOption(null, "targetPort", true, "");
        options.addOption(null, "bind", true, "");
        options.addOption(null, "server", true, "");
        options.addOption(null, "server.port", true, "");

        CommandLine parse = parser.parse(options, args);

        String optionValue = parse.getOptionValue("server", "true");
        log.info("server={}, please wait...", optionValue);

        if (optionValue.equals("true")) {
            server(args);
        } else {
            client(parse);
        }
    }

    volatile static int readSize = 0;
    volatile static int writeSize = 0;

    static int bufSize = 1024 * 1024; // 1MB


    private static void client(CommandLine parse) throws IOException {
        log.info("type=client");

        String host = parse.getOptionValue("proxyHost");
        int port = Integer.parseInt(parse.getOptionValue("proxyPort"));
        int bind = Integer.parseInt(parse.getOptionValue("bind"));
        String targetHost = parse.getOptionValue("targetHost");
        int targetPort = Integer.parseInt(parse.getOptionValue("targetPort"));

        ServerSocket serverSocket = new ServerSocket(bind);
        log.info("localhost:{} -> {}:{} -> {}:{}", bind, host, port, targetHost, targetPort);


        while (true) {
            Socket socket = serverSocket.accept();
            String uuid = UUID.randomUUID().toString();
            readSize++;
            writeSize++;
            log.info("read={} write={}", readSize, writeSize);
            if (readSize > 100 || writeSize > 100) {
                throw new RuntimeException();
            }


            // read
            new Thread(() -> {
                try {
                    while (true) {
                        InputStream inputStream = socket.getInputStream();
                        byte[] bytes = readNBytes(inputStream, bufSize);
                        if (bytes.length == 0) {
//                            log.info("nothing to send sleep 1s");
                            Thread.sleep(10);
                        } else {
                            log.info("write {} bytes", bytes.length);
                            String binaryData = binaryEncode(bytes);
                            String url = String.format("http://%s:%s?uuid=%s&host=%s&port=%s&binaryData=%s"
                                    , host, port, uuid, targetHost, targetPort, binaryData);
                            new RestTemplate().exchange(url, HttpMethod.PUT, HttpEntity.EMPTY, Object.class);
                        }
                    }
                } catch (Exception e) {
                    log.error("", e);
                    throw new RuntimeException(e);
                } finally {
                    readSize--;
                }
            }).start();

            // write
            new Thread(() -> {
                try {
                    while (true) {
                        OutputStream outputStream = socket.getOutputStream();
                        String url = String.format("http://%s:%s?uuid=%s&host=%s&port=%s"
                                , host, port, uuid, targetHost, targetPort);
                        ResponseEntity<String> data = new RestTemplate().exchange(url, HttpMethod.GET, HttpEntity.EMPTY,
                                String.class);
                        if (!data.getStatusCode().is2xxSuccessful()) {
                            throw new RuntimeException();
                        }

                        String body = data.getBody();
                        if (body == null || body.isEmpty()) {
//                            log.info("nothing to read sleep 1s");
                            Thread.sleep(10);
                        } else {
                            byte[] bytes = binaryDecode(body);
                            log.info("read {} bytes", bytes.length);
                            outputStream.write(bytes);
                        }

                    }
                } catch (Exception e) {
                    log.error("", e);
                    throw new RuntimeException(e);
                } finally {
                    writeSize--;
                }

            }).start();


        }
    }

    private static byte[] readNBytes(InputStream inputStream, int n) throws IOException {
        int read = Math.min(inputStream.available(), n);
        return IOUtils.readFully(inputStream, read);
    }

    private static void server(String[] args) throws Exception {
        log.info("type=server");
        SpringApplication.run(SimpleTcpProxy.class, args);
    }


    Map<String, Socket> connect = new HashMap<>();

    @PutMapping
    void write(@RequestParam String uuid, @RequestParam String host, @RequestParam int port,
               @RequestParam String binaryData) throws IOException {
        String hashKey = uuid + host + port;
        if (!connect.containsKey(hashKey)) {
            connect.put(hashKey, new Socket(InetAddress.getByName(host), port));
        }

        try {
            connect.get(hashKey).getOutputStream().write(binaryDecode(binaryData));
        } catch (Exception e) {
            connect.remove(hashKey);
            throw e;
        }
    }

    @GetMapping
    String read(@RequestParam String uuid, @RequestParam String host, @RequestParam int port) throws IOException {
        String hashKey = uuid + host + port;
        if (!connect.containsKey(hashKey)) {
            connect.put(hashKey, new Socket(InetAddress.getByName(host), port));
        }


        try {
            byte[] bytes = readNBytes(connect.get(hashKey).getInputStream(), bufSize);
            return binaryEncode(bytes);
        } catch (Exception e) {
            connect.remove(hashKey);
            throw e;
        }
    }

    static byte[] binaryDecode(String data) {
        return ByteArrayUtil.hexStringToByteArray(data);

    }

    static String binaryEncode(byte[] data) {
        return ByteArrayUtil.toHexString(data);
    }


    public static class ProxyClientHandler extends ChannelInboundHandlerAdapter {
        private final String remoteHost;
        private final int remotePort;
        private Channel outboundChannel;

        public ProxyClientHandler(String remoteHost, int remotePort) {
            this.remoteHost = remoteHost;
            this.remotePort = remotePort;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            final Channel inboundChannel = ctx.channel();
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(inboundChannel.eventLoop())
                    .channel(ctx.channel().getClass())
                    .handler(new ProxyBackendHandler(inboundChannel))
                    .option(ChannelOption.AUTO_READ, false);
            ChannelFuture future = bootstrap.connect(remoteHost, remotePort);
            outboundChannel = future.channel();
            future.addListener((ChannelFutureListener) future1 -> {
                if (future1.isSuccess()) {
                    inboundChannel.read();
                } else {
                    inboundChannel.close();
                }
            });
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            outboundChannel.writeAndFlush(msg).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    ctx.channel().read();
                } else {
                    future.channel().close();
                }
            });
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (outboundChannel != null) {
                outboundChannel.close();
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }

    public static class ProxyBackendHandler extends ChannelInboundHandlerAdapter {
        private final Channel inboundChannel;

        public ProxyBackendHandler(Channel inboundChannel) {
            this.inboundChannel = inboundChannel;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            ctx.read();
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            inboundChannel.writeAndFlush(msg).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    ctx.channel().read();
                } else {
                    future.channel().close();
                }
            });
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            inboundChannel.close();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }
}