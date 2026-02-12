package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.dto.PrivateKeyRequest;
import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
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
            Authentication authentication) {
        try {
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
    public ResponseEntity<Resource> downloadFile(
            @PathVariable Long fileId,
            @RequestBody PrivateKeyRequest privateKeyRequest,
            Authentication authentication) {
        try {
            String username = authentication.getName();
            String providedPrivateKey = privateKeyRequest.getPrivateKey();
            
            // Validate that private key is provided
            if (providedPrivateKey == null || providedPrivateKey.trim().isEmpty()) {
                return ResponseEntity.badRequest().build();
            }
            
            // Download and decrypt file with provided private key
            byte[] decryptedFile = fileService.downloadFileWithPrivateKey(fileId, username, providedPrivateKey);
            
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
            // Invalid private key provided
            return ResponseEntity.status(403).build();
        } catch (Exception e) {
            e.printStackTrace();
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
}     