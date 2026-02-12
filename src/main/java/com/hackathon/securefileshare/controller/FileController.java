package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.dto.PrivateKeyRequest;
import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/files")
@CrossOrigin(origins = "*", allowedHeaders = "*") // Ensure CORS is allowed at controller level too
public class FileController {

    @Autowired
    private FileService fileService;
    
    @Autowired
    private com.hackathon.securefileshare.service.UploadRateLimiterService uploadRateLimiterService;
    
    @Autowired
    private com.hackathon.securefileshare.service.BruteForceProtectionService bruteForceProtectionService;

    /**
     * Upload a file with hybrid encryption
     * POST /api/files/upload
     * 
     * @param file - The file to upload
     * @param receiverUsername - Username of the receiver
     * @param authentication - Current authenticated user (sender)
     * @return FileMetadata of the uploaded file
     */
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("receiverUsername") String receiverUsername,
            Authentication authentication,
            jakarta.servlet.http.HttpServletRequest request) { // Add HttpServletRequest
        try {
            String clientIp = getClientIp(request);
            
            // 1. Check Brute Force Block (Global IP Block)
            if (bruteForceProtectionService.isBlocked(clientIp)) {
                 long remainingMillis = bruteForceProtectionService.getBlockTimeRemaining(clientIp);
                 long seconds = (remainingMillis / 1000) % 60;
                 long minutes = (remainingMillis / (1000 * 60)) % 60;
                 String timeString = String.format("%d minutes %d seconds", minutes, seconds);
                 
                 return ResponseEntity.status(429).body("{\"message\": \"Too many failed attempts. You are temporarily blocked. Try again in " + timeString + ".\"}");
            }
            
            // 2. Check Upload Rate Limit
            if (!uploadRateLimiterService.isAllowed(clientIp)) {
                return ResponseEntity.status(429).body("{\"message\": \"Upload limit exceeded. Please wait 5 minutes.\"}");
            }
        
            if (authentication == null) {
                return ResponseEntity.status(403).body("{\"message\": \"User not authenticated\"}");
            }
            
            String senderUsername = authentication.getName();
            
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("{\"message\": \"File is empty\"}");
            }
            
            FileMetadata metadata = fileService.uploadFile(file, senderUsername, receiverUsername);
            return ResponseEntity.ok(metadata);
            
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("{\"message\": \"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("{\"message\": \"Upload failed: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Download and decrypt a file with user-provided private key
     * POST /api/files/download/{fileId}
     * 
     * @param fileId - ID of the file to download
     * @param privateKeyRequest - Request body containing the private key
     * @param authentication - Current authenticated user (must be receiver)
     * @return Decrypted file as downloadable resource
     */
    @PostMapping("/download/{fileId}")
    public ResponseEntity<?> downloadFile(
            @PathVariable Long fileId,
            @RequestBody PrivateKeyRequest privateKeyRequest,
            Authentication authentication,
            jakarta.servlet.http.HttpServletRequest request) { // Add HttpServletRequest
        
        String clientIp = getClientIp(request);
        
        // 1. Check Block
        if (bruteForceProtectionService.isBlocked(clientIp)) {
             long remainingMillis = bruteForceProtectionService.getBlockTimeRemaining(clientIp);
             long seconds = (remainingMillis / 1000) % 60;
             long minutes = (remainingMillis / (1000 * 60)) % 60;
             String timeString = String.format("%d minutes %d seconds", minutes, seconds);
             
             return ResponseEntity.status(429).body("{\"message\": \"Too many failed attempts. You are temporarily blocked. Try again in " + timeString + ".\"}");
        }

        try {
            String username = authentication.getName();
            String providedPrivateKey = privateKeyRequest.getPrivateKey();
            
            // Validate that private key is provided
            if (providedPrivateKey == null || providedPrivateKey.trim().isEmpty()) {
                return ResponseEntity.badRequest().build();
            }
            
            // Download and decrypt file with provided private key
            byte[] decryptedFile = fileService.downloadFileWithPrivateKey(fileId, username, providedPrivateKey);
            
            // SUCCESS: Reset attempts
            bruteForceProtectionService.recordSuccess(clientIp);
            
            // Get file metadata for filename
            FileMetadata metadata = fileService.getFileMetadata(fileId);
            
            ByteArrayResource resource = new ByteArrayResource(decryptedFile);
            
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, 
                           "attachment; filename=\"" + metadata.getFileName() + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(decryptedFile.length)
                    .body(resource);
                    
        } catch (IllegalArgumentException e) {
            // Invalid private key provided or other auth error
            // RECORD FAILURE
            bruteForceProtectionService.recordFailedAttempt(clientIp);
            return ResponseEntity.status(403).body("{\"message\": \"Invalid private key or unauthorized. Attempt recorded.\"}");
        } catch (Exception e) {
            e.printStackTrace();
            // Could be other errors, maybe check if it is related to decryption failures?
            // For now, treat generic errors as potential failures if appropriate, or just 500.
            // But usually brute force is specifically about auth/decryption failures.
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get inbox - files received by the current user
     * GET /api/files/inbox
     * 
     * @param authentication - Current authenticated user
     * @return List of files sent to this user
     */
    @GetMapping("/inbox")
    public ResponseEntity<List<FileMetadata>> getInbox(Authentication authentication) {
        try {
            String username = authentication.getName();
            List<FileMetadata> files = fileService.getInbox(username);
            return ResponseEntity.ok(files);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get sent files - files sent by the current user
     * GET /api/files/sent
     * 
     * @param authentication - Current authenticated user
     * @return List of files sent by this user
     */
    @GetMapping("/sent")
    public ResponseEntity<List<FileMetadata>> getSentFiles(Authentication authentication) {
        try {
            String username = authentication.getName();
            List<FileMetadata> files = fileService.getSentFiles(username);
            return ResponseEntity.ok(files);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().build();
        }
    }
    
    private String getClientIp(jakarta.servlet.http.HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        String ip;
        if (xfHeader == null) {
            ip = request.getRemoteAddr();
        } else {
            ip = xfHeader.split(",")[0];
        }
        System.out.println("DEBUG: Client IP detected: " + ip);
        return ip;
    }
}     