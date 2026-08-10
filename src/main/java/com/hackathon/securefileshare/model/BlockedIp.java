package com.hackathon.securefileshare.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "blocked_ips")
public class BlockedIp {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String ipAddress;

    private String reason;

    private LocalDateTime blockedAt;

    @PrePersist
    protected void onCreate() {
        blockedAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public LocalDateTime getBlockedAt() {
        return blockedAt;
    }

    public void setBlockedAt(LocalDateTime blockedAt) {
        this.blockedAt = blockedAt;
    }
}
