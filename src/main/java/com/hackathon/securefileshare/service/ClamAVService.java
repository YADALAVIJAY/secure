package com.hackathon.securefileshare.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

@Service
public class ClamAVService {

    private static final Logger logger = LoggerFactory.getLogger(ClamAVService.class);

    @Value("${clamav.host:localhost}")
    private String clamavHost;

    @Value("${clamav.port:3310}")
    private int clamavPort;

    @Value("${clamav.timeout:5000}")
    private int timeout;

    @Value("${clamav.enabled:true}")
    private boolean enabled;

    private static final byte[] INSTREAM_CMD =
            "zINSTREAM\0".getBytes(StandardCharsets.US_ASCII);

    private static final int CHUNK_SIZE = 2048;

    /**
     * Scan file using ClamAV INSTREAM protocol
     */
    public String scanFile(InputStream inputStream) throws IOException {
        
        if (!enabled) {
            logger.warn("ClamAV scanning is DISABLED. File accepted without scan.");
            return "stream: OK";
        }

        logger.info("Connecting to ClamAV at {}:{}", clamavHost, clamavPort);

        try (Socket socket = new Socket()) {

            socket.connect(new InetSocketAddress(clamavHost, clamavPort), timeout);
            socket.setSoTimeout(timeout);

            try (OutputStream out = socket.getOutputStream();
                 InputStream in = socket.getInputStream()) {

                // 1️⃣ Send INSTREAM command
                out.write(INSTREAM_CMD);
                out.flush();

                // 2️⃣ Send file data in chunks
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;

                while ((bytesRead = inputStream.read(buffer)) != -1) {

                    // Send chunk length (4 bytes)
                    out.write(ByteBuffer.allocate(4).putInt(bytesRead).array());

                    // Send chunk data
                    out.write(buffer, 0, bytesRead);
                }

                // 3️⃣ Send zero-length chunk (EOF)
                out.write(new byte[]{0, 0, 0, 0});
                out.flush();

                // 4️⃣ Read ClamAV response
                ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
                byte[] responseBuffer = new byte[CHUNK_SIZE];
                int read;

                while ((read = in.read(responseBuffer)) != -1) {
                    responseStream.write(responseBuffer, 0, read);
                }

                String result = responseStream
                        .toString(StandardCharsets.US_ASCII)
                        .trim();

                logger.info("ClamAV Response: {}", result);

                return result;
            }

        } catch (IOException e) {
            logger.error("ClamAV scanning failed", e);

            // SECURITY POLICY: FAIL CLOSED
            throw new IOException("ClamAV service unavailable. Upload blocked.", e);
        }
    }

    /**
     * Check if scan result is clean
     */
    public boolean isClean(String scanResult) {
        return scanResult != null && scanResult.endsWith("OK");
    }

    /**
     * Extract virus name from scan result
     * Example:
     * "stream: Eicar-Test-Signature FOUND"
     */
    public String getVirusName(String scanResult) {

        if (scanResult == null || !scanResult.contains("FOUND")) {
            return null;
        }

        try {
            int start = scanResult.indexOf("stream: ") + 8;
            int end = scanResult.lastIndexOf(" FOUND");
            return scanResult.substring(start, end).trim();
        } catch (Exception e) {
            logger.warn("Unable to extract virus name from result: {}", scanResult);
            return "Unknown-Malware";
        }
    }
}
