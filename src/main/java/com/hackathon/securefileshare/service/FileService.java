package com.hackathon.securefileshare.service;

import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.repository.FileMetadataRepository;
import com.hackathon.securefileshare.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class FileService {

    @Autowired
    private FileMetadataRepository fileMetadataRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoService cryptoService;

    @Value("${file.upload-dir}")
    private String uploadDir;

    public FileMetadata uploadFile(MultipartFile file, String senderUsername, String receiverUsername) throws Exception {
        // 1. Get Users
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new RuntimeException("Sender not found"));
        User receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new RuntimeException("Receiver not found"));

        // 2. Generate AES Key (Session Key)
        SecretKey aesKey = cryptoService.generateAESKey();

        // 3. Encrypt File with AES
        byte[] fileBytes = file.getBytes();
        byte[] encryptedFileBytes = cryptoService.encryptAES(fileBytes, aesKey);

        // 4. Encrypt AES Key with Receiver's Public Key
        byte[] encryptedAesKeyBytes = cryptoService.encryptRSA(aesKey.getEncoded(), receiver.getPublicKey());
        String encryptedAesKeyStr = Base64.getEncoder().encodeToString(encryptedAesKeyBytes);

        // 5. Create Digital Signature: Hash(Original File) -> Sign with Sender's Private Key
        // Note: Ideally, sign the hash of the encrypted file or original file. Prompt says "Hash of original file".
        byte[] signatureBytes = cryptoService.sign(fileBytes, sender.getEncryptedPrivateKey());
        String signatureStr = Base64.getEncoder().encodeToString(signatureBytes);

        // 6. Save Encrypted File to Disk
        String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        Files.createDirectories(filePath.getParent());
        Files.write(filePath, encryptedFileBytes);

        // 7. Save Metadata to DB
        FileMetadata metadata = new FileMetadata();
        metadata.setFileName(file.getOriginalFilename());
        metadata.setSenderUsername(senderUsername);
        metadata.setReceiverUsername(receiverUsername);
        metadata.setFilePath(filePath.toString());
        metadata.setEncryptedAesKey(encryptedAesKeyStr);
        metadata.setSignature(signatureStr);

        return fileMetadataRepository.save(metadata);
    }

    public byte[] downloadFile(Long fileId, String username) throws Exception {
        // 1. Fetch Metadata
        FileMetadata metadata = fileMetadataRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));

        // Security Check
        if (!metadata.getReceiverUsername().equals(username) && !metadata.getSenderUsername().equals(username)) {
            throw new RuntimeException("Unauthorized access");
        }
        
        // As a sender, we might just want to see what we sent, but we can't decrypt the AES key 
        // because it's encrypted with Receiver's Public Key! 
        // So strictly only Receiver can download and decrypt.
        if (!metadata.getReceiverUsername().equals(username)) {
             throw new RuntimeException("Only receiver can decrypt this file.");
        }

        User receiver = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        User sender = userRepository.findByUsername(metadata.getSenderUsername())
                .orElseThrow(() -> new RuntimeException("Sender not found"));

        // 2. Decrypt AES Key using Receiver's Private Key
        byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(metadata.getEncryptedAesKey());
        byte[] aesKeyBytes = cryptoService.decryptRSA(encryptedAesKeyBytes, receiver.getEncryptedPrivateKey());
        SecretKey aesKey = cryptoService.stringToSecretKey(Base64.getEncoder().encodeToString(aesKeyBytes));

        // 3. Read Encrypted File
        byte[] encryptedFileBytes = Files.readAllBytes(Paths.get(metadata.getFilePath()));

        // 4. Decrypt File using AES Key
        byte[] decryptedFileBytes = cryptoService.decryptAES(encryptedFileBytes, aesKey);

        // 5. Verify Signature (Integrity & Authenticity)
        byte[] signatureBytes = Base64.getDecoder().decode(metadata.getSignature());
        boolean isVerified = cryptoService.verify(decryptedFileBytes, signatureBytes, sender.getPublicKey());

        if (!isVerified) {
            throw new RuntimeException("File tampering detected! Signature verification failed.");
        }

        return decryptedFileBytes;
    }
    
    public List<FileMetadata> getInbox(String username) {
        return fileMetadataRepository.findByReceiverUsername(username);
    }
    
    public List<FileMetadata> getSentFiles(String username) {
        return fileMetadataRepository.findBySenderUsername(username);
    }
}
