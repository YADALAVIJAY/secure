package com.hackathon.securefileshare.service;

import com.hackathon.securefileshare.model.BlockedIp;
import com.hackathon.securefileshare.repository.BlockedIpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class BlockedIpService {

    private final BlockedIpRepository blockedIpRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void blockIpPermanently(String ipAddress, String reason) {
        if (!blockedIpRepository.existsByIpAddress(ipAddress)) {
            BlockedIp blockedIp = new BlockedIp();
            blockedIp.setIpAddress(ipAddress);
            blockedIp.setReason(reason);
            blockedIpRepository.save(blockedIp);
            System.err.println("PERMANENT SECURITY BLOCK: IP " + ipAddress + " blacklisted permanently. Reason: " + reason);
        }
    }

    public boolean isIpPermanentlyBlocked(String ipAddress) {
        return blockedIpRepository.existsByIpAddress(ipAddress);
    }
}
