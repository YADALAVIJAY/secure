package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileController {

    @Autowired
    private FileService fileService;

    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file,
                                        @RequestParam("receiver") String receiverUsername) {
        try {
            String senderUsername = getCurrentUsername();
            fileService.uploadFile(file, senderUsername, receiverUsername);
            return ResponseEntity.ok("File uploaded successfully. Encrypted and Signed.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Upload failed: " + e.getMessage());
        }
    }

    @GetMapping("/download/{id}")
    public ResponseEntity<?> downloadFile(@PathVariable Long id) {
        try {
            String username = getCurrentUsername();
            byte[] fileData = fileService.downloadFile(id, username);
            
            // Assume we want to return it as a download
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"decrypted_file\"")
                    .body(fileData);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Download failed: " + e.getMessage());
        }
    }

    @GetMapping("/inbox")
    public ResponseEntity<List<FileMetadata>> getInbox() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(fileService.getInbox(username));
    }

    @GetMapping("/sent")
    public ResponseEntity<List<FileMetadata>> getSent() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(fileService.getSentFiles(username));
    }

    private String getCurrentUsername() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        } else {
            return principal.toString();
        }
    }
}
