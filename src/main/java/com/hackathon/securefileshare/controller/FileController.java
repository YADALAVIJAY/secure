package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.dto.PrivateKeyRequest;
import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.service.ClamAVService;
import com.hackathon.securefileshare.service.FileService;
import com.hackathon.securefileshare.service.UploadRateLimiterService;
import com.hackathon.securefileshare.service.BruteForceProtectionService;

import org.springframework.beans.factory.annotation.Autowired;
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
public class FileController {

    @Autowired
    private FileService fileService;

    @Autowired
    private ClamAVService clamAVService;

    @Autowired
    private UploadRateLimiterService uploadRateLimiterService;

    @Autowired
    private BruteForceProtectionService bruteForceProtectionService;

    // ===========================
    // 🔥 UPLOAD FILE
    // ===========================
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("receiverUsername") String receiverUsername,
            Authentication authentication,
            HttpServletRequest request) {

        try {

            String clientIp = getClientIp(request);

            // 1️⃣ Check if IP is blocked
            if (bruteForceProtectionService.isBlocked(clientIp)) {
                long remainingMillis =
                        bruteForceProtectionService.getBlockTimeRemaining(clientIp);

                long seconds = (remainingMillis / 1000) % 60;
                long minutes = (remainingMillis / (1000 * 60)) % 60;

                return ResponseEntity.status(429)
                        .body("{\"message\":\"Too many failed attempts. Try again in "
                                + minutes + "m " + seconds + "s.\"}");
            }

            // 2️⃣ Upload rate limiting
            if (!uploadRateLimiterService.isAllowed(clientIp)) {
                return ResponseEntity.status(429)
                        .body("{\"message\":\"Upload limit exceeded. Wait 5 minutes.\"}");
            }

            // 3️⃣ Authentication check
            if (authentication == null) {
                return ResponseEntity.status(403)
                        .body("{\"message\":\"User not authenticated\"}");
            }

            String senderUsername = authentication.getName();

            // 4️⃣ File validations
            if (file.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body("{\"message\":\"File is empty\"}");
            }

            if (file.getSize() > 50 * 1024 * 1024) {
                return ResponseEntity.badRequest()
                        .body("{\"message\":\"File exceeds 50MB limit\"}");
            }

            // 5️⃣ 🔥 ClamAV Scan BEFORE encryption
            String scanResult =
                    clamAVService.scanFile(file.getInputStream());

            if (!clamAVService.isClean(scanResult)) {
                String virus =
                        clamAVService.getVirusName(scanResult);

                return ResponseEntity.badRequest()
                        .body("{\"message\":\"Virus detected: " + virus + "\"}");
            }

            // 6️⃣ Proceed with hybrid encryption
            FileMetadata metadata =
                    fileService.uploadFile(file, senderUsername, receiverUsername);

            return ResponseEntity.ok(metadata);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body("{\"message\":\"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError()
                    .body("{\"message\":\"Upload failed: "
                            + e.getMessage() + "\"}");
        }
    }

    // ===========================
    // 🔐 DOWNLOAD & DECRYPT FILE
    // ===========================
    @PostMapping("/download/{fileId}")
    public ResponseEntity<?> downloadFile(
            @PathVariable Long fileId,
            @RequestBody PrivateKeyRequest privateKeyRequest,
            Authentication authentication,
            HttpServletRequest request) {

        String clientIp = getClientIp(request);

        if (bruteForceProtectionService.isBlocked(clientIp)) {
            return ResponseEntity.status(429)
                    .body("{\"message\":\"Too many failed attempts. Try later.\"}");
        }

        try {

            String username = authentication.getName();
            String providedPrivateKey = privateKeyRequest.getPrivateKey();

            if (providedPrivateKey == null ||
                    providedPrivateKey.trim().isEmpty()) {
                return ResponseEntity.badRequest().build();
            }

            byte[] decryptedFile =
                    fileService.downloadFileWithPrivateKey(
                            fileId,
                            username,
                            providedPrivateKey
                    );

            // SUCCESS → Reset brute force counter
            bruteForceProtectionService.recordSuccess(clientIp);

            FileMetadata metadata =
                    fileService.getFileMetadata(fileId);

            ByteArrayResource resource =
                    new ByteArrayResource(decryptedFile);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" +
                                    metadata.getFileName() + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(decryptedFile.length)
                    .body(resource);

        } catch (IllegalArgumentException e) {
            bruteForceProtectionService.recordFailedAttempt(clientIp);

            return ResponseEntity.status(403)
                    .body("{\"message\":\"Invalid private key or unauthorized.\"}");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    // ===========================
    // 🔒 DOWNLOAD ENCRYPTED FILE
    // ===========================
    @GetMapping("/download-encrypted/{fileId}")
    public ResponseEntity<?> downloadEncryptedFile(
            @PathVariable Long fileId,
            Authentication authentication) {

        try {

            String username = authentication.getName();

            byte[] encryptedFile =
                    fileService.downloadEncryptedFile(fileId, username);

            FileMetadata metadata =
                    fileService.getFileMetadata(fileId);

            ByteArrayResource resource =
                    new ByteArrayResource(encryptedFile);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"ENCRYPTED_"
                                    + metadata.getFileName() + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(encryptedFile.length)
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(403)
                    .body("{\"message\":\"Download failed\"}");
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
