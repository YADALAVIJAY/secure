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
import java.util.Arrays;
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

    @Autowired
    private ClamAVService clamAVService;

    @Autowired
    private com.hackathon.securefileshare.repository.MalwareLogRepository malwareLogRepository;

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    private static final List<String> BLOCKED_EXTENSIONS = Arrays.asList(".exe", ".bat", ".sh", ".cmd", ".msi", ".jar", ".js", ".vbs", ".php", ".py", ".pl", ".rb");

    public FileMetadata uploadFile(MultipartFile file, String senderUsername, String receiverUsername) throws Exception {
        // 0. General Validation
        validateFile(file);

        // 1. Get Users
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Receiver not found"));

        // 1.5 Scan for Malware (ClamAV) - Stream Check
        try (java.io.InputStream is = file.getInputStream()) {
            System.out.println("Scanning file: " + file.getOriginalFilename());
            String scanResult = clamAVService.scanFile(is);
            
            if (!clamAVService.isClean(scanResult)) {
                String virusName = clamAVService.getVirusName(scanResult);
                System.err.println("MALWARE DETECTED: " + virusName);

                // Log to Database
                com.hackathon.securefileshare.model.MalwareLog log = new com.hackathon.securefileshare.model.MalwareLog();
                log.setFileName(file.getOriginalFilename());
                log.setUploaderUsername(senderUsername);
                log.setVirusName(virusName);
                log.setFileType(file.getContentType());
                log.setFileSize(file.getSize());
                log.setClientIp("Unknown (Service Layer)"); 
                malwareLogRepository.save(log);

                throw new SecurityException("Security Alert: Malware detected in file! Upload rejected.");
            }
            System.out.println("File is clean. Proceeding to encryption.");
        } catch (java.io.IOException e) {
             System.err.println("ClamAV Scan failed: " + e.getMessage());
             throw new RuntimeException("File scan failed. Service unavailable.");
        }

        // 2. Generate AES Key (Session Key)
        SecretKey aesKey = cryptoService.generateAESKey();

        // 3. Prepare File Path
        String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        if (!Files.exists(filePath.getParent())) {
            Files.createDirectories(filePath.getParent());
        }

        // 4. Encrypt and Sign Stream
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
    
    private void validateFile(MultipartFile file) {
        String fileName = file.getOriginalFilename();
        if (fileName != null) {
            String lowerCaseName = fileName.toLowerCase();
            for (String ext : BLOCKED_EXTENSIONS) {
                if (lowerCaseName.endsWith(ext)) {
                    throw new SecurityException("Security Alert: File type '" + ext + "' is not allowed.");
                }
            }
        }
        
        // Basic MIME type check
        String contentType = file.getContentType();
        if (contentType != null && (
                contentType.equals("application/x-msdownload") || 
                contentType.equals("application/x-sh") || 
                contentType.equals("application/javascript"))) {
             throw new SecurityException("Security Alert: File MIME type not allowed.");       
        }
    }

    public byte[] downloadFile(Long fileId, String username) throws Exception {
        // Obsolete method signature without private key, keeping for backward compatibility if needed, 
        // but ideally we redirect to downloadFileWithPrivateKey or simply fail.
        throw new UnsupportedOperationException("Use downloadFileWithPrivateKey instead.");
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
     */
    public byte[] downloadFileWithPrivateKey(Long fileId, String username, String providedPrivateKey) throws Exception {
        // 1. Get File Metadata
        FileMetadata metadata = fileMetadataRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));

        // 2. Security Check: Only receiver can download
        if (!metadata.getReceiverUsername().equals(username)) {
            throw new RuntimeException("Only receiver can decrypt this file.");
        }

        // 3. Get receiver from database 
        User receiver = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Receiver not found"));

        // 4. Validate private key
        String normalizedProvidedKey = normalizeKey(providedPrivateKey);
        String storedPrivateKey = cryptoService.decryptDatabaseField(receiver.getEncryptedPrivateKey());
        String normalizedStoredKey = normalizeKey(storedPrivateKey);

        if (!normalizedProvidedKey.equals(normalizedStoredKey)) {
             throw new IllegalArgumentException("Invalid private key provided. Decryption failed.");
        }

        // 5. Decrypt AES Key 
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

        // Security Check
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
                  .replaceAll("\\s+", ""); 
    }

    @Value("${file.expiration.minutes:2}")
    private int expirationMinutes;

    @jakarta.annotation.PostConstruct
    public void init() {
        System.out.println("FileService initialized.");
        deleteExpiredFiles(); 
    }

    @org.springframework.scheduling.annotation.Scheduled(cron = "${file.cleanup.cron:0 * * * * *}")
    public void deleteExpiredFiles() {
        try {
            java.time.LocalDateTime cutoffTime = java.time.LocalDateTime.now().minusMinutes(expirationMinutes);
            List<FileMetadata> expiredFiles = fileMetadataRepository.findByCreatedAtBefore(cutoffTime);

            for (FileMetadata file : expiredFiles) {
                try {
                    Path path = Paths.get(file.getFilePath());
                    if (Files.exists(path)) {
                        Files.delete(path);
                    }
                    fileMetadataRepository.delete(file);
                } catch (Exception e) {
                    System.err.println("Error deleting file: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
