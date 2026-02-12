package com.hackathon.securefileshare.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UploadRateLimiterService {

    private static final int MAX_UPLOADS = 5;
    private static final long TIME_WINDOW_MILLIS = 5 * 60 * 1000; // 5 minutes

    // Stores IP -> List of upload timestamps
    private final Map<String, List<Long>> uploadHistory = new ConcurrentHashMap<>();

    /**
     * Checks if the IP is allowed to upload.
     * If allowed, records the upload timestamp.
     * 
     * @param ipAddress The client IP address
     * @return true if allowed, false if limit exceeded
     */
    public boolean isAllowed(String ipAddress) {
        long now = System.currentTimeMillis();

        // Get or create history for this IP
        uploadHistory.putIfAbsent(ipAddress, new ArrayList<>());
        List<Long> timestamps = uploadHistory.get(ipAddress);

        synchronized (timestamps) {
            // Remove old timestamps (older than 5 mins)
            Iterator<Long> iterator = timestamps.iterator();
            while (iterator.hasNext()) {
                Long timestamp = iterator.next();
                if (now - timestamp > TIME_WINDOW_MILLIS) {
                    iterator.remove();
                }
            }

            // Check if limit exceeded
            if (timestamps.size() >= MAX_UPLOADS) {
                return false;
            }

            // Record new upload
            timestamps.add(now);
            return true;
        }
    }
}
