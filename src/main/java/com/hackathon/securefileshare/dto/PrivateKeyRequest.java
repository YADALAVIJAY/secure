package com.hackathon.securefileshare.dto;

public class PrivateKeyRequest {
    private String privateKey;

    public PrivateKeyRequest() {
    }

    public PrivateKeyRequest(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
