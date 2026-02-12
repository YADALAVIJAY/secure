package com.hackathon.securefileshare.repository;

import com.hackathon.securefileshare.model.FileMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FileMetadataRepository extends JpaRepository<FileMetadata, Long> {
    List<FileMetadata> findByReceiverUsername(String receiverUsername);
    List<FileMetadata> findBySenderUsername(String senderUsername);
    
    List<FileMetadata> findByCreatedAtBefore(java.time.LocalDateTime dateTime);
}
