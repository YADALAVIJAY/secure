package com.hackathon.securefileshare.controller;


import com.hackathon.securefileshare.model.FileMetadata;

import com.hackathon.securefileshare.service.FileService;
import com.hackathon.securefileshare.service.UploadRateLimiterService;
import com.hackathon.securefileshare.service.BruteForceProtectionService;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/files")
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RequiredArgsConstructor
public class FileController {

    private final FileService fileService;
    private final UploadRateLimiterService uploadRateLimiterService;
    private final BruteForceProtectionService bruteForceProtectionService;

    // ===========================
    // 🛡️ VERIFY FILE (ClamAV Scan)
    // ===========================
    @PostMapping("/verify")
    public ResponseEntity<?> verifyFile(
            @RequestParam MultipartFile file,
            Authentication authentication,
            HttpServletRequest request) {

        String clientIp = getClientIp(request);
        try {
            if (bruteForceProtectionService.isBlocked(clientIp)) {
                return ResponseEntity.status(429).body("{\"message\":\"Too many attempts. Blocked.\"}");
            }
            if (authentication == null) {
                return ResponseEntity.status(403).body("{\"message\":\"User not authenticated\"}");
            }

            String senderUsername = authentication.getName();
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("{\"message\":\"File is empty\"}");
            }

            java.util.Map<String, Object> result = fileService.verifyFileOnly(file, senderUsername, clientIp);
            return ResponseEntity.ok(result);

        } catch (com.hackathon.securefileshare.exception.ClamAVServerOfflineException e) {
            throw e;
        } catch (com.hackathon.securefileshare.exception.MalwareDetectedException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("{\"message\":\"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("{\"message\":\"Verification failed: " + e.getMessage() + "\"}");
        }
    }

    // ===========================
    // 🔥 UPLOAD & SHARE FILE (Encrypted + Zero Trust)
    // ===========================
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(
            @RequestParam MultipartFile file,
            @RequestParam String receiverUsername,
            @RequestParam String signature,
            Authentication authentication,
            HttpServletRequest request) {

        String clientIp = getClientIp(request);
        try {

            // 1️⃣ Check if IP is blocked
            if (bruteForceProtectionService.isBlocked(clientIp)) {
                return ResponseEntity.status(429).body("{\"message\":\"Too many attempts. Blocked.\"}");
            }

            // 2️⃣ Upload rate limiting
            if (!uploadRateLimiterService.isAllowed(clientIp)) {
                return ResponseEntity.status(429).body("{\"message\":\"Upload limit exceeded.\"}");
            }

            // 3️⃣ Authentication check
            if (authentication == null) {
                return ResponseEntity.status(403).body("{\"message\":\"User not authenticated\"}");
            }

            String senderUsername = authentication.getName();

            // 4️⃣ File validations
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("{\"message\":\"File is empty\"}");
            }

            // 5️⃣ Proceed with storage (Server Encrypted)
            FileMetadata metadata =
                    fileService.uploadFile(file, senderUsername, receiverUsername, signature, clientIp);

            return ResponseEntity.ok(metadata);

        } catch (com.hackathon.securefileshare.exception.ClamAVServerOfflineException e) {
            throw e;
        } catch (com.hackathon.securefileshare.exception.MalwareDetectedException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("{\"message\":\"" + e.getMessage() + "\"}");
        } catch (SecurityException e) {
             return ResponseEntity.status(400).body("{\"message\":\"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("{\"message\":\"Upload failed: " + e.getMessage() + "\"}");
        }
    }

    // ===========================
    // 🔐 DOWNLOAD & DECRYPT FILE
    // ===========================
    // ===========================
    // 🔐 DOWNLOAD FILE (Encrypted)
    // ===========================
    @GetMapping("/download/{fileId}")
    public ResponseEntity<?> downloadFile(
            @PathVariable Long fileId,
            Authentication authentication) {

        try {
            String username = authentication.getName();

            // Download encrypted file directly
            byte[] encryptedFile = fileService.downloadEncryptedFile(fileId, username);

            FileMetadata metadata = fileService.getFileMetadata(fileId);

            ByteArrayResource resource = new ByteArrayResource(encryptedFile);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + metadata.getFileName() + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(encryptedFile.length)
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(403).body("{\"message\":\"Download failed or unauthorized\"}");
        }
    }

    // ===========================
    // 📥 INBOX
    // ===========================
    @GetMapping("/inbox")
    public ResponseEntity<List<FileMetadata>> getInbox(
            Authentication authentication) {

        try {
            String username = authentication.getName();
            return ResponseEntity.ok(fileService.getInbox(username));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // ===========================
    // 📤 SENT FILES
    // ===========================
    @GetMapping("/sent")
    public ResponseEntity<List<FileMetadata>> getSentFiles(
            Authentication authentication) {

        try {
            String username = authentication.getName();
            return ResponseEntity.ok(fileService.getSentFiles(username));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // ===========================
    // 🌍 CLIENT IP DETECTION
    // ===========================
    private String getClientIp(HttpServletRequest request) {

        String xfHeader = request.getHeader("X-Forwarded-For");

        if (xfHeader == null) {
            return request.getRemoteAddr();
        }

        return xfHeader.split(",")[0];
    }
}
