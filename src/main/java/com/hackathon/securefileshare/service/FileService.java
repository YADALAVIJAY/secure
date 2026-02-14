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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

@Service
@Transactional
public class FileService {

    @Autowired
    private FileMetadataRepository fileMetadataRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ClamAVService clamAVService;

    @Autowired
    private CryptoService cryptoService;

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    private static final List<String> BLOCKED_EXTENSIONS = Arrays.asList(".exe", ".bat", ".sh", ".cmd", ".msi", ".jar", ".js", ".vbs", ".php", ".py", ".pl", ".rb");

    public FileMetadata uploadFile(MultipartFile file, String senderUsername, String receiverUsername, String signature) throws Exception {
        // 0. General Validation
        validateFile(file);

        // 1. Get Users
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Receiver not found"));

        // 2. Read File Data
        byte[] fileBytes = file.getBytes();

        // 3. ClamAV Scan (Server-Side on Plaintext)
        try (java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(fileBytes)) {
             System.out.println("Scanning file (Plaintext): " + file.getOriginalFilename());
             String scanResult = clamAVService.scanFile(bis);
             
             if (!clamAVService.isClean(scanResult)) {
                 String virusName = clamAVService.getVirusName(scanResult);
                 System.err.println("Malware Detected: " + virusName);
                 throw new SecurityException("Security Alert: Malware detected (" + virusName + "). Upload rejected.");
             }
             System.out.println("Scan Result: Clean");
        }

        // 4. Generate AES Key (Server-Side)
        javax.crypto.SecretKey aesKey = cryptoService.generateAESKey();

        // 5. Encrypt File Content (Server-Side)
        byte[] encryptedFileBytes = cryptoService.encryptAES(fileBytes, aesKey);

        // 6. Encrypt AES Key for Receiver
        String encryptedAesKey = cryptoService.encryptRSA(cryptoService.keyToString(aesKey), receiver.getPublicKey());

        // 7. Prepare File Path
        String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        if (!Files.exists(filePath.getParent())) {
            Files.createDirectories(filePath.getParent());
        }

        // 8. Save Encrypted File to Disk
        Files.write(filePath, encryptedFileBytes);

        // 9. Save Metadata to DB
        FileMetadata metadata = new FileMetadata();
        metadata.setFileName(file.getOriginalFilename());
        metadata.setSenderUsername(senderUsername);
        metadata.setReceiverUsername(receiverUsername);
        metadata.setFilePath(filePath.toString());
        metadata.setEncryptedAesKey(encryptedAesKey); // Encrypted for Receiver
        metadata.setSignature(signature);             // Signed by Sender (Client-Side)
        metadata.setCreatedAt(java.time.LocalDateTime.now());

        System.out.println("Processing file upload (Server Encrypted): " + metadata.getFileName());
        
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
