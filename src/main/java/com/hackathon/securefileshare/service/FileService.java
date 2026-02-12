package com.hackathon.securefileshare.service;

import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.repository.FileMetadataRepository;
import com.hackathon.securefileshare.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;

@Service
@Transactional
public class FileService {

    @Autowired
    private FileMetadataRepository fileMetadataRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoService cryptoService;

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    public FileMetadata uploadFile(MultipartFile file, String senderUsername, String receiverUsername) throws Exception {
        // 1. Get Users
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Receiver not found"));

        // 2. Generate AES Key (Session Key)
        SecretKey aesKey = cryptoService.generateAESKey();

        // 3. Prepare File Path
        String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        if (!Files.exists(filePath.getParent())) {
            Files.createDirectories(filePath.getParent());
        }

        // 4. Encrypt and Sign Stream
        // Decrypt the sender's private key from DB format (AES) to RSA plaintext for signing
        String senderPrivateKey = cryptoService.decryptDatabaseField(sender.getEncryptedPrivateKey());
        java.security.Signature signature = cryptoService.getSignatureInstance(senderPrivateKey);
        javax.crypto.Cipher aesCipher = cryptoService.getAESCipher(javax.crypto.Cipher.ENCRYPT_MODE, aesKey);

        try (java.io.InputStream is = file.getInputStream();
             java.io.FileOutputStream fos = new java.io.FileOutputStream(filePath.toFile());
             javax.crypto.CipherOutputStream cos = new javax.crypto.CipherOutputStream(fos, aesCipher)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
                cos.write(buffer, 0, bytesRead);
            }
        }

        // 5. Encrypt AES Key with Receiver's Public Key
        byte[] encryptedAesKeyBytes = cryptoService.encryptRSA(aesKey.getEncoded(), receiver.getPublicKey());
        String encryptedAesKeyStr = Base64.getEncoder().encodeToString(encryptedAesKeyBytes);

        // 6. Finalize Signature
        byte[] signatureBytes = signature.sign();
        String signatureStr = Base64.getEncoder().encodeToString(signatureBytes);

        // 7. Save Metadata to DB
        FileMetadata metadata = new FileMetadata();
        metadata.setFileName(file.getOriginalFilename());
        metadata.setSenderUsername(senderUsername);
        metadata.setReceiverUsername(receiverUsername);
        metadata.setFilePath(filePath.toString());
        metadata.setEncryptedAesKey(encryptedAesKeyStr);
        metadata.setSignature(signatureStr);
        metadata.setCreatedAt(java.time.LocalDateTime.now());

        System.out.println("Processing file upload: " + metadata.getFileName());
        
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
        
        if (!metadata.getReceiverUsername().equals(username)) {
             throw new RuntimeException("Only receiver can decrypt this file.");
        }

        User receiver = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        User sender = userRepository.findByUsername(metadata.getSenderUsername())
                .orElseThrow(() -> new RuntimeException("Sender not found"));

        // 2. Decrypt AES Key using Receiver's Private Key
        // Decrypt receiver's private key from DB format first
        String receiverPrivateKey = cryptoService.decryptDatabaseField(receiver.getEncryptedPrivateKey());
        
        byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(metadata.getEncryptedAesKey());
        byte[] aesKeyBytes = cryptoService.decryptRSA(encryptedAesKeyBytes, receiverPrivateKey);
        SecretKey aesKey = cryptoService.stringToSecretKey(Base64.getEncoder().encodeToString(aesKeyBytes));

        // 3. Decrypt and Verify Stream
        javax.crypto.Cipher aesCipher = cryptoService.getAESCipher(javax.crypto.Cipher.DECRYPT_MODE, aesKey);
        java.security.Signature signature = cryptoService.getVerifySignatureInstance(sender.getPublicKey());
        
        // Use ByteArrayOutputStream to hold decrypted data in memory (Still limited by RAM, but unavoidable if we return byte[]).
        // To support TRUE large file download, we should return StreamingResponseBody or InputStreamResource.
        // For now, we at least stream the PROCESS so we don't hold encrypted + decrypted + signature buffers all at once.
        java.io.ByteArrayOutputStream decryptedOutput = new java.io.ByteArrayOutputStream();

        try (java.io.FileInputStream fis = new java.io.FileInputStream(metadata.getFilePath());
             javax.crypto.CipherInputStream cis = new javax.crypto.CipherInputStream(fis, aesCipher)) {
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
                decryptedOutput.write(buffer, 0, bytesRead);
            }
        }

        // 4. Verify Signature
        byte[] signatureBytes = Base64.getDecoder().decode(metadata.getSignature());
        boolean isVerified = signature.verify(signatureBytes);

        if (!isVerified) {
            throw new RuntimeException("File tampering detected! Signature verification failed.");
        }

        return decryptedOutput.toByteArray();
    }
    
    public List<FileMetadata> getInbox(String username) {
        return fileMetadataRepository.findByReceiverUsername(username);
    }
    
    
    
    public List<FileMetadata> getSentFiles(String username) {
        return fileMetadataRepository.findBySenderUsername(username);
    }
    
    public FileMetadata getFileMetadata(Long fileId) {
        return fileMetadataRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));
    }
    
    /**
     * Download file with user-provided private key validation
     * This ensures only the correct private key can decrypt the file
     */
    public byte[] downloadFileWithPrivateKey(Long fileId, String username, String providedPrivateKey) throws Exception {
        // 1. Get File Metadata
        FileMetadata metadata = fileMetadataRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));

        // 2. Security Check: Only receiver can download
        if (!metadata.getReceiverUsername().equals(username)) {
            throw new RuntimeException("Only receiver can decrypt this file.");
        }

        // 3. Get receiver from database to compare private keys
        User receiver = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Receiver not found"));

        // 4. CRITICAL: Validate that provided private key matches stored private key
        String normalizedProvidedKey = normalizeKey(providedPrivateKey);
        // Decrypt stored key from DB format before comparison
        String storedPrivateKey = cryptoService.decryptDatabaseField(receiver.getEncryptedPrivateKey());
        String normalizedStoredKey = normalizeKey(storedPrivateKey);

        System.out.println("DEBUG: Key Validation");
        System.out.println("Provided key (first 30 chars): " + (normalizedProvidedKey.length() > 30 ? normalizedProvidedKey.substring(0, 30) : normalizedProvidedKey));
        System.out.println("Stored key   (first 30 chars): " + (normalizedStoredKey.length() > 30 ? normalizedStoredKey.substring(0, 30) : normalizedStoredKey));
        System.out.println("Provided Length: " + normalizedProvidedKey.length());
        System.out.println("Stored Length:   " + normalizedStoredKey.length());

        if (!normalizedProvidedKey.equals(normalizedStoredKey)) {
             System.out.println("ERROR: Keys do not match!");
             throw new IllegalArgumentException("Invalid private key provided. Decryption failed.");
        }

        // 5. Decrypt AES Key using the VALIDATED private key
        byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(metadata.getEncryptedAesKey());
        byte[] aesKeyBytes = cryptoService.decryptRSA(encryptedAesKeyBytes, providedPrivateKey);
        SecretKey aesKey = cryptoService.stringToSecretKey(Base64.getEncoder().encodeToString(aesKeyBytes));

        // 6. Read encrypted file
        Path filePath = Paths.get(metadata.getFilePath());
        byte[] encryptedFileBytes = Files.readAllBytes(filePath);

        // 7. Decrypt and Verify Stream
        javax.crypto.Cipher aesCipher = cryptoService.getAESCipher(javax.crypto.Cipher.DECRYPT_MODE, aesKey);
        java.security.Signature signature = cryptoService.getVerifySignatureInstance(
                userRepository.findByUsername(metadata.getSenderUsername())
                        .orElseThrow(() -> new RuntimeException("Sender not found"))
                        .getPublicKey()
        );

        java.io.ByteArrayOutputStream decryptedOutput = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayInputStream encryptedInput = new java.io.ByteArrayInputStream(encryptedFileBytes);

        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = encryptedInput.read(buffer)) != -1) {
            byte[] decryptedChunk = aesCipher.update(buffer, 0, bytesRead);
            if (decryptedChunk != null) {
                decryptedOutput.write(decryptedChunk);
                signature.update(decryptedChunk);
            }
        }
        byte[] finalChunk = aesCipher.doFinal();
        if (finalChunk != null) {
            decryptedOutput.write(finalChunk);
            signature.update(finalChunk);
        }

        // 8. Verify Signature
        byte[] signatureBytes = Base64.getDecoder().decode(metadata.getSignature());
        boolean isVerified = signature.verify(signatureBytes);

        if (!isVerified) {
            throw new RuntimeException("File tampering detected! Signature verification failed.");
        }

        return decryptedOutput.toByteArray();
    }

    public byte[] downloadEncryptedFile(Long fileId, String username) throws Exception {
        // 1. Fetch Metadata
        FileMetadata metadata = fileMetadataRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));

        // Security Check: Allow both sender and receiver to download the encrypted blob
        if (!metadata.getReceiverUsername().equals(username) && !metadata.getSenderUsername().equals(username)) {
            throw new RuntimeException("Unauthorized access");
        }

        // 2. Read RAW encrypted file from disk
        Path filePath = Paths.get(metadata.getFilePath());
        if (!Files.exists(filePath)) {
            throw new RuntimeException("File not found on server");
        }
        
        return Files.readAllBytes(filePath);
    }

    private String normalizeKey(String key) {
        if (key == null) return "";
        return key.replace("-----BEGIN PRIVATE KEY-----", "")
                  .replace("-----END PRIVATE KEY-----", "")
                  .replaceAll("\\s+", ""); // Remove all whitespace/newlines
    }

    @Value("${file.expiration.minutes:2}")
    private int expirationMinutes;

    @jakarta.annotation.PostConstruct
    public void init() {
        System.out.println("FileService initialized.");
        System.out.println("File Expiration Minutes: " + expirationMinutes);
        deleteExpiredFiles(); // Run once on startup
    }

    @org.springframework.scheduling.annotation.Scheduled(cron = "${file.cleanup.cron:0 * * * * *}")
    public void deleteExpiredFiles() {
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        System.out.println("Scheduler triggered at: " + now);
        System.out.println("Expiration minutes configured: " + expirationMinutes);
        
        try {
            java.time.LocalDateTime cutoffTime = now.minusMinutes(expirationMinutes);
            System.out.println("Cutoff time calculated: " + cutoffTime);
            
            List<FileMetadata> expiredFiles = fileMetadataRepository.findByCreatedAtBefore(cutoffTime);
            System.out.println("Found " + expiredFiles.size() + " expired files to delete.");

            for (FileMetadata file : expiredFiles) {
                try {
                    // Delete physical file
                    Path path = Paths.get(file.getFilePath());
                    if (Files.exists(path)) {
                        Files.delete(path);
                        System.out.println("Deleted physical file: " + file.getFileName());
                    } else {
                        System.out.println("Physical file not found for: " + file.getFileName());
                    }
                    
                    // Delete metadata
                    fileMetadataRepository.delete(file);
                    System.out.println("Deleted metadata for: " + file.getFileName());
                } catch (Exception e) {
                    System.err.println("Error deleting file " + file.getFileName() + ": " + e.getMessage());
                }
            }
            System.out.println("File cleanup completed.");
        } catch (Exception e) {
            System.err.println("Error during file cleanup task: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
