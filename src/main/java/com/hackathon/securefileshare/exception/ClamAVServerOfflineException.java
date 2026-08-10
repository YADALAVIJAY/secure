package com.hackathon.securefileshare.exception;

public class ClamAVServerOfflineException extends RuntimeException {
    public ClamAVServerOfflineException(String message) {
        super(message);
    }

    public ClamAVServerOfflineException(String message, Throwable cause) {
        super(message, cause);
    }
}
