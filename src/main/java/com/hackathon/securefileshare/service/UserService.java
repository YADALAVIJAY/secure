package com.hackathon.securefileshare.service;

import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Base64;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CryptoService cryptoService;

    public User registerUser(User user) throws Exception {
        // 1. Generate RSA Key Pair
        KeyPair keyPair = cryptoService.generateRSAKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        // 2. Set Keys
        user.setPublicKey(publicKey);
        
        // Encrypt the Private Key before storing in DB to prevent leaks
        String dbEncryptedPrivateKey = cryptoService.encryptDatabaseField(privateKey);
        user.setEncryptedPrivateKey(dbEncryptedPrivateKey);

        // 3. Hash Password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        return userRepository.save(user);
    }
    
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public String getDecryptedPrivateKey(User user) {
        return cryptoService.decryptDatabaseField(user.getEncryptedPrivateKey());
    }
}
