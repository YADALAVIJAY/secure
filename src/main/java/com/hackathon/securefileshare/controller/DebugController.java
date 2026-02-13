package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.model.FileMetadata;
import com.hackathon.securefileshare.repository.FileMetadataRepository;
import com.hackathon.securefileshare.service.FileService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/debug")
public class DebugController {

    @Autowired
    private FileMetadataRepository fileMetadataRepository;

    @Autowired
    private FileService fileService;

    @Value("${file.expiration.minutes:2}")
    private int expirationMinutes;

    @GetMapping("/info")
    public Map<String, Object> getDebugInfo() {

        Map<String, Object> info = new HashMap<>();

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime cutoff = now.minusMinutes(expirationMinutes);

        info.put("currentServerTime", now);
        info.put("expirationMinutes", expirationMinutes);
        info.put("cutoffTime", cutoff);

        List<FileMetadata> allFiles = fileMetadataRepository.findAll();
        info.put("totalFiles", allFiles.size());

        List<FileMetadata> expiredFiles =
                fileMetadataRepository.findByCreatedAtBefore(cutoff);

        info.put("expiredFilesFoundQuery", expiredFiles.size());

        if (!expiredFiles.isEmpty()) {
            info.put("sampleExpiredFile",
                    expiredFiles.get(0).getFileName());
            info.put("sampleExpiredFileCreated",
                    expiredFiles.get(0).getCreatedAt());
        }

        return info;
    }

    @GetMapping("/trigger-cleanup")
    public String triggerCleanup() {
        fileService.deleteExpiredFiles();
        return "Cleanup triggered manually. Check console logs.";
    }
}
