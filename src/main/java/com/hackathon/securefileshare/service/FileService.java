package com.hackathon.securefileshare.service;

import com.hackathon.securefileshare.exception.MalwareDetectedException;
import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.repository.FileMetadataRepository;
import com.hackathon.securefileshare.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class FileService {

    private final FileMetadataRepository fileMetadataRepository;
    private final UserRepository userRepository;
    private final ClamAVService clamAVService;
    private final CryptoService cryptoService;
    private final MalwareLogService malwareLogService;
    private final UserService userService;
    private final BlockedIpService blockedIpService;

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    private static final List<String> BLOCKED_EXTENSIONS = Arrays.asList(".exe", ".bat", ".sh", ".cmd", ".msi", ".jar", ".js", ".vbs", ".php", ".py", ".pl", ".rb");

    public FileMetadata uploadFile(MultipartFile file, String senderUsername, String receiverUsername, String signature, String clientIp) throws Exception {
        // 0. General Validation (File Extension & MIME check)
        validateFile(file, senderUsername, clientIp);

        // 1. Get Users
        userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Receiver not found"));

        // 2. Prepare Temporary File Path (Quarantine Zone / Staging)
        String originalFileName = file.getOriginalFilename();
        String tempFileName = "TEMP_" + System.currentTimeMillis() + "_" + originalFileName;
        Path tempFilePath = Paths.get(uploadDir, "temp", tempFileName);
        
        if (!Files.exists(tempFilePath.getParent())) {
            Files.createDirectories(tempFilePath.getParent());
        }

        // 3. Save File to Temporary Location (Plaintext)
        file.transferTo(tempFilePath);
        System.out.println("File saved to temporary location: " + tempFilePath.toString());

        try {
            // 4. ClamAV Scan (Scan the file on disk)
            try (java.io.InputStream fileInputStream = Files.newInputStream(tempFilePath)) {
                 System.out.println("Scanning file (On Disk): " + originalFileName);
                 String scanResult = clamAVService.scanFile(fileInputStream);
                 
                 if (!clamAVService.isClean(scanResult)) {
                     String virusName = clamAVService.getVirusName(scanResult);
                     System.err.println("Malware Detected: " + virusName);

                     // 4a. Log Malware Incident in independent transaction (REQUIRES_NEW)
                     malwareLogService.logMalware(
                             originalFileName,
                             senderUsername,
                             clientIp,
                             virusName,
                             getContentType(tempFilePath),
                             Files.size(tempFilePath)
                     );

                     // 4b. PERMANENTLY BLOCK USER & BLACKLIST IP ADDRESS
                     userService.blockUserPermanently(senderUsername);
                     blockedIpService.blockIpPermanently(clientIp, "Malware Detected: " + virusName);

                     // 4c. Delete Temporary File IMMEDIATELY
                     Files.deleteIfExists(tempFilePath);
                     System.err.println("Infected file deleted: " + tempFilePath.toString());

                     throw new MalwareDetectedException("Security Alert: Malware detected (" + virusName + "). Account PERMANENTLY BLOCKED.", virusName);
                 }
                 System.out.println("Scan Result: Clean");
            }

            // 5. If Clean -> Proceed with Encryption

            // 5a. Read File Bytes (from temp file)
            byte[] fileBytes = Files.readAllBytes(tempFilePath);

            // 5b. Generate AES Key (Server-Side)
            javax.crypto.SecretKey aesKey = cryptoService.generateAESKey();

            // 5c. Encrypt File Content (Server-Side)
            byte[] encryptedFileBytes = cryptoService.encryptAES(fileBytes, aesKey);

            // 5d. Encrypt AES Key for Receiver
            String encryptedAesKey = cryptoService.encryptRSA(cryptoService.keyToString(aesKey), receiver.getPublicKey());

            // 6. Save Encrypted File to Final Destination
            String finalFileName = System.currentTimeMillis() + "_" + originalFileName;
            Path finalFilePath = Paths.get(uploadDir, finalFileName);
            Files.write(finalFilePath, encryptedFileBytes);
            System.out.println("Encrypted file saved to final location: " + finalFilePath.toString());

            // 7. Delete Temporary Plaintext File
            Files.deleteIfExists(tempFilePath);
            System.out.println("Temporary plaintext file deleted.");

            // 8. Save Metadata to DB
            FileMetadata metadata = new FileMetadata();
            metadata.setFileName(originalFileName);
            metadata.setSenderUsername(senderUsername);
            metadata.setReceiverUsername(receiverUsername);
            metadata.setFilePath(finalFilePath.toString());
            metadata.setEncryptedAesKey(encryptedAesKey); // Encrypted for Receiver
            metadata.setSignature(signature);             // Signed by Sender (Client-Side)
            metadata.setCreatedAt(java.time.LocalDateTime.now());

            System.out.println("Processing file upload (Secure Workflow Complete): " + metadata.getFileName());
            
            return fileMetadataRepository.save(metadata);

        } catch (Exception e) {
            // Ensure temp file is cleaned up on any error
            try {
                Files.deleteIfExists(tempFilePath);
            } catch (java.io.IOException ignored) {}
            throw e;
        }
    }

    public java.util.Map<String, Object> verifyFileOnly(MultipartFile file, String senderUsername, String clientIp) throws Exception {
        // 0. Extension Check for Verification Only (No Permanent User Block)
        String fileName = file.getOriginalFilename();
        if (fileName != null) {
            String lowerCaseName = fileName.toLowerCase();
            for (String ext : BLOCKED_EXTENSIONS) {
                if (lowerCaseName.endsWith(ext)) {
                    malwareLogService.logMalware(
                        fileName,
                        senderUsername,
                        clientIp,
                        "Blocked Extension (" + ext + ")",
                        file.getContentType() != null ? file.getContentType() : "unknown",
                        file.getSize()
                    );
                    throw new MalwareDetectedException("Security Alert: File type '" + ext + "' is not allowed.", "Blocked Extension (" + ext + ")");
                }
            }
        }

        // 1. Prepare Temporary File Path
        String tempFileName = "VERIFY_" + System.currentTimeMillis() + "_" + (fileName != null ? fileName : "file");
        Path tempFilePath = Paths.get(uploadDir, "temp", tempFileName);

        if (!Files.exists(tempFilePath.getParent())) {
            Files.createDirectories(tempFilePath.getParent());
        }

        // 2. Save to temp location
        file.transferTo(tempFilePath);

        try {
            // 3. ClamAV Scan
            try (java.io.InputStream fileInputStream = Files.newInputStream(tempFilePath)) {
                 String scanResult = clamAVService.scanFile(fileInputStream);

                 if (!clamAVService.isClean(scanResult)) {
                     String virusName = clamAVService.getVirusName(scanResult);

                     malwareLogService.logMalware(
                             fileName != null ? fileName : "unknown",
                             senderUsername,
                             clientIp,
                             virusName,
                             getContentType(tempFilePath),
                             Files.size(tempFilePath)
                     );

                     Files.deleteIfExists(tempFilePath);
                     throw new MalwareDetectedException("Security Alert: Malware detected (" + virusName + "). File blocked.", virusName);
                 }
            }

            Files.deleteIfExists(tempFilePath);

            java.util.Map<String, Object> response = new java.util.HashMap<>();
            response.put("status", "VERIFIED");
            response.put("fileName", fileName);
            response.put("fileSize", file.getSize());
            response.put("scanResult", "CLEAN");
            response.put("clamavStatus", "PASSED");
            response.put("message", "File passed ClamAV security scan");
            return response;

        } catch (Exception e) {
            try {
                Files.deleteIfExists(tempFilePath);
            } catch (java.io.IOException ignored) {}
            throw e;
        }
    }

    private String getContentType(Path path) {
        try {
            return Files.probeContentType(path);
        } catch (java.io.IOException e) {
            return "unknown";
        }
    }
    
    private void validateFile(MultipartFile file, String senderUsername, String clientIp) {
        String fileName = file.getOriginalFilename();
        if (fileName != null) {
            String lowerCaseName = fileName.toLowerCase();
            for (String ext : BLOCKED_EXTENSIONS) {
                if (lowerCaseName.endsWith(ext)) {
                    malwareLogService.logMalware(
                        fileName,
                        senderUsername,
                        clientIp,
                        "Blocked Extension (" + ext + ")",
                        file.getContentType() != null ? file.getContentType() : "unknown",
                        file.getSize()
                    );
                    userService.blockUserPermanently(senderUsername);
                    blockedIpService.blockIpPermanently(clientIp, "Blocked Extension (" + ext + ")");
                    throw new MalwareDetectedException("Security Alert: File type '" + ext + "' is not allowed. Account PERMANENTLY BLOCKED.", "Blocked Extension (" + ext + ")");
                }
            }
        }
        
        // Basic MIME type check
        String contentType = file.getContentType();
        if (contentType != null && (
                contentType.equals("application/x-msdownload") || 
                contentType.equals("application/x-sh") || 
                contentType.equals("application/javascript"))) {
             malwareLogService.logMalware(
                 fileName != null ? fileName : "unknown",
                 senderUsername,
                 clientIp,
                 "Blocked MIME Type (" + contentType + ")",
                 contentType,
                 file.getSize()
             );
             userService.blockUserPermanently(senderUsername);
             blockedIpService.blockIpPermanently(clientIp, "Blocked MIME Type (" + contentType + ")");
             throw new MalwareDetectedException("Security Alert: File MIME type not allowed. Account PERMANENTLY BLOCKED.", "Blocked MIME Type (" + contentType + ")");
        }
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

    public byte[] downloadEncryptedFile(Long fileId, String username) throws Exception {
        // 1. Fetch Metadata
        FileMetadata metadata = fileMetadataRepository.findById(fileId)
                .orElseThrow(() -> new RuntimeException("File not found"));

        System.out.println("Processing download request for file: " + metadata.getFileName());

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
