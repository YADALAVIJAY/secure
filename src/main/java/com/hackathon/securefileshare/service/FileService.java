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



    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    private static final List<String> BLOCKED_EXTENSIONS = Arrays.asList(".exe", ".bat", ".sh", ".cmd", ".msi", ".jar", ".js", ".vbs", ".php", ".py", ".pl", ".rb");

    public FileMetadata uploadFile(MultipartFile file, String senderUsername, String receiverUsername, String encryptedAesKey, String signature) throws Exception {
        // 0. General Validation
        validateFile(file);

        // 1. Get Users
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Receiver not found"));

        // 1.5 ClamAV Scan (Note: Scanning encrypted files is limited, but we keeping it for basic signature checks if any)
        try (java.io.InputStream is = file.getInputStream()) {
            // System.out.println("Scanning file (Encrypted): " + file.getOriginalFilename());
            // String scanResult = clamAVService.scanFile(is);
            // if (!clamAVService.isClean(scanResult)) { ... } 
            // Skipping strictly blocking scan for now as it might false positive on high entropy encrypted data or be useless.
            // For now, we trust the client-side encryption flow or implement a proper malware scanning pipeline that decrypts in a sandbox if needed.
            // keeping it simple for Hackathon:
        }

        // 2. Prepare File Path
        String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get(uploadDir, fileName);
        if (!Files.exists(filePath.getParent())) {
            Files.createDirectories(filePath.getParent());
        }

        // 3. Save Encrypted File to Disk
        file.transferTo(filePath);

        // 4. Save Metadata to DB
        FileMetadata metadata = new FileMetadata();
        metadata.setFileName(file.getOriginalFilename());
        metadata.setSenderUsername(senderUsername);
        metadata.setReceiverUsername(receiverUsername);
        metadata.setFilePath(filePath.toString());
        metadata.setEncryptedAesKey(encryptedAesKey); // Provided by Client
        metadata.setSignature(signature);             // Provided by Client
        metadata.setCreatedAt(java.time.LocalDateTime.now());

        System.out.println("Processing file upload (Client Encrypted): " + metadata.getFileName());
        
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
