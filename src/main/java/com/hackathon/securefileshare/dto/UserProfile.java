package com.hackathon.securefileshare.dto;

public class UserProfile {
    private String username;
    private String email;
    private String publicKey;
    private String encryptedPrivateKey;

    public UserProfile(String username, String email, String publicKey, String encryptedPrivateKey) {
        this.username = username;
        this.email = email;
        this.publicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    // Getters and Setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getEncryptedPrivateKey() { return encryptedPrivateKey; }
    public void setEncryptedPrivateKey(String encryptedPrivateKey) { this.encryptedPrivateKey = encryptedPrivateKey; }
}
