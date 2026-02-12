package com.hackathon.securefileshare.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class BruteForceProtectionService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long BLOCK_DURATION_MILLIS = 2 * 60 * 1000; // 2 minutes

    // IP -> Failed Attempts Count
    private final Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    
    // IP -> Timestamp when block expires
    private final Map<String, Long> blockedIps = new ConcurrentHashMap<>();

    /**
     * Checks if the IP is currently blocked.
     * Automatically unblocks if the duration has passed.
     */
    public boolean isBlocked(String ipAddress) {
        if (blockedIps.containsKey(ipAddress)) {
            long unblockTime = blockedIps.get(ipAddress);
            if (System.currentTimeMillis() < unblockTime) {
                System.out.println("DEBUG: IP " + ipAddress + " is BLOCKED until " + unblockTime);
                return true; // Still blocked
            } else {
                // Unblock automatically
                System.out.println("DEBUG: IP " + ipAddress + " block expired. Unblocking.");
                blockedIps.remove(ipAddress);
                attemptsCache.remove(ipAddress);
            }
        }
        return false;
    }

    /**
     * Records a failed attempt. If limit reached, blocks the IP.
     */
    public void recordFailedAttempt(String ipAddress) {
        int attempts = attemptsCache.getOrDefault(ipAddress, 0);
        attempts++;
        attemptsCache.put(ipAddress, attempts);
        System.out.println("DEBUG: IP " + ipAddress + " failed attempt " + attempts + "/" + MAX_FAILED_ATTEMPTS);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            long unblockTime = System.currentTimeMillis() + BLOCK_DURATION_MILLIS;
            blockedIps.put(ipAddress, unblockTime);
            System.out.println("WARN: IP " + ipAddress + " has been blocked due to generic brute force detection.");
        }
    }

    /**
     * Resets attempts on successful action.
     */
    public void recordSuccess(String ipAddress) {
        attemptsCache.remove(ipAddress);
        blockedIps.remove(ipAddress);
    }
    public long getBlockTimeRemaining(String ipAddress) {
        if (blockedIps.containsKey(ipAddress)) {
            long unblockTime = blockedIps.get(ipAddress);
            long remaining = unblockTime - System.currentTimeMillis();
            return remaining > 0 ? remaining : 0;
        }
        return 0;
    }
}
