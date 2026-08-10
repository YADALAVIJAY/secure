package com.hackathon.securefileshare.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ClamAVServerOfflineException.class)
    public ResponseEntity<Map<String, Object>> handleClamAVOffline(ClamAVServerOfflineException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("message", ex.getMessage());
        body.put("errorType", "CLAMAV_OFFLINE");
        body.put("status", 503);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    @ExceptionHandler(MalwareDetectedException.class)
    public ResponseEntity<Map<String, Object>> handleMalwareDetected(MalwareDetectedException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("message", ex.getMessage());
        body.put("virusName", ex.getVirusName());
        body.put("errorType", "MALWARE_DETECTED");
        body.put("status", 403);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }
}
