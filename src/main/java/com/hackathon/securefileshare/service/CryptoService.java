package com.hackathon.securefileshare.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class CryptoService {

    private static final String RSA_ALGO = "RSA";
    private static final String AES_ALGO = "AES";
    private static final String SIGNING_ALGO = "SHA256withRSA";

    // --- RSA Operations ---

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGO);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public String encryptRSA(String data, String publicKeyStr) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyStr);
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    // Overload for raw bytes (for AES key Encryption)
    public byte[] encryptRSA(byte[] data, String publicKeyStr) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyStr);
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptRSA(byte[] encryptedData, String privateKeyStr) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyStr);
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    // --- AES Operations ---

    public SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGO);
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public byte[] encryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public byte[] decryptAES(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // --- Digital Signature ---

    public byte[] sign(byte[] data, String privateKeyStr) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyStr);
        Signature signature = Signature.getInstance(SIGNING_ALGO);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verify(byte[] data, byte[] signatureBytes, String publicKeyStr) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyStr);
        Signature signature = Signature.getInstance(SIGNING_ALGO);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
    
    // --- Streaming Support ---
    
    public Cipher getAESCipher(int mode, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(mode, key);
        return cipher;
    }
    
    public Signature getSignatureInstance(String privateKeyStr) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyStr);
        Signature signature = Signature.getInstance(SIGNING_ALGO);
        signature.initSign(privateKey);
        return signature;
    }
    
    public Signature getVerifySignatureInstance(String publicKeyStr) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyStr);
        Signature signature = Signature.getInstance(SIGNING_ALGO);
        signature.initVerify(publicKey);
        return signature;
    }
    
    // --- Utils ---

    public String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public SecretKey stringToSecretKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, AES_ALGO);
    }

    private PublicKey getPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGO);
        return kf.generatePublic(spec);
    }

    private PrivateKey getPrivateKey(String base64PrivateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGO);
        return kf.generatePrivate(spec);
    }
}
