package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.dto.AuthRequest;
import com.hackathon.securefileshare.dto.AuthResponse;
import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.security.JwtUtil;
import com.hackathon.securefileshare.service.UserService;
import com.hackathon.securefileshare.service.BruteForceProtectionService;
import com.hackathon.securefileshare.service.BlockedIpService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final com.hackathon.securefileshare.repository.UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BruteForceProtectionService bruteForceProtectionService;
    private final BlockedIpService blockedIpService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request, jakarta.servlet.http.HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIp(httpRequest);
            if (blockedIpService.isIpPermanentlyBlocked(clientIp)) {
                return ResponseEntity.status(403)
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Registration blocked. Your IP address has been PERMANENTLY BLACKLISTED due to security violations.\"}");
            }
            // 1. Username Validation & Uniqueness Check
            if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Username is required\"}");
            }
            String username = request.getUsername().trim();
            if (username.length() < 3 || username.length() > 30 || !username.matches("^[a-zA-Z0-9_-]+$")) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Username must be 3-30 characters (letters, numbers, _, -)\"}");
            }
            if (userRepository.existsByUsername(username)) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Username is already taken. Please choose another username.\"}");
            }

            // 2. Email Format & Uniqueness Check
            if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Email address is required\"}");
            }
            String email = request.getEmail().trim();
            if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Please enter a valid email address (e.g. name@domain.com)\"}");
            }
            if (userRepository.existsByEmail(email)) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Email address is already registered. Please sign in or use another email.\"}");
            }

            // 3. Password Complexity Check (Min 8 chars, letters, numbers, special characters)
            String password = request.getPassword();
            if (password == null || password.length() < 8) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Password must be at least 8 characters long\"}");
            }
            if (!password.matches("^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*?&#_~^+=><-]).{8,}$")) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Password must contain letters, numbers, and special characters (e.g. @, #, $, !)\"}");
            }
            
            User user = new User();
            user.setUsername(request.getUsername());
            user.setPassword(request.getPassword());
            user.setEmail(request.getEmail());
            userService.registerUser(user);
            return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body("{\"message\": \"User registered successfully\"}");
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            return ResponseEntity.badRequest()
                .header("Content-Type", "application/json")
                .body("{\"message\": \"Username or email already exists\"}");
        } catch (Exception e) {
            e.printStackTrace(); // Log the error for debugging
            return ResponseEntity.badRequest()
                .header("Content-Type", "application/json")
                .body("{\"message\": \"Registration failed: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request, jakarta.servlet.http.HttpServletRequest httpRequest) {
        String clientIp = getClientIp(httpRequest);
        System.out.println("DEBUG: Login attempt from IP: " + clientIp);

        if (blockedIpService.isIpPermanentlyBlocked(clientIp)) {
            return ResponseEntity.status(403).body("{\"message\": \"Access Denied. Your IP address has been PERMANENTLY BLACKLISTED due to security violations.\"}");
        }

        try {
            User user = userService.findByUsername(request.getUsername());
            if (user.isBlocked()) {
                return ResponseEntity.status(403).body("{\"message\": \"Your account has been PERMANENTLY BLOCKED due to security violations.\"}");
            }
        } catch (Exception ignored) {}

        if (bruteForceProtectionService.isBlocked(clientIp)) {
             System.out.println("DEBUG: IP " + clientIp + " is already BLOCKED.");
             long remainingMillis = bruteForceProtectionService.getBlockTimeRemaining(clientIp);
             long seconds = (remainingMillis / 1000) % 60;
             long minutes = (remainingMillis / (1000 * 60)) % 60;
             String timeString = String.format("%d minutes %d seconds", minutes, seconds);
             
             return ResponseEntity.status(429).body("{\"message\": \"Too many failed attempts. You are temporarily blocked. Try again in " + timeString + ".\"}");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            // Success
            System.out.println("DEBUG: Login successful for IP: " + clientIp);
            bruteForceProtectionService.recordSuccess(clientIp);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal(); // Cast is important
            String jwt = jwtUtil.generateToken(userDetails.getUsername());

            return ResponseEntity.ok(new AuthResponse(jwt, userDetails.getUsername()));
        } catch (Exception e) {
            // Failure
            System.out.println("DEBUG: Login failed for IP: " + clientIp);
            bruteForceProtectionService.recordFailedAttempt(clientIp);
            return ResponseEntity.badRequest().body("Invalid credentials");
        }
    }

    private String getClientIp(jakarta.servlet.http.HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(Authentication authentication) {
        try {
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            // Decrypt the private key from DB format to usable RSA plaintext for the frontend
            String plaintextPrivateKey = userService.getDecryptedPrivateKey(user);
            
            return ResponseEntity.ok(new com.hackathon.securefileshare.dto.UserProfile(
                user.getUsername(),
                user.getEmail(),
                user.getPublicKey(),
                plaintextPrivateKey
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to fetch profile");
        }
    }
    @PostMapping("/verify-password")
    public ResponseEntity<?> verifyPassword(@RequestBody AuthRequest request, jakarta.servlet.http.HttpServletRequest httpRequest, Authentication authentication) {
        String clientIp = getClientIp(httpRequest);
        
        if (bruteForceProtectionService.isBlocked(clientIp)) {
             long remainingMillis = bruteForceProtectionService.getBlockTimeRemaining(clientIp);
             long seconds = (remainingMillis / 1000) % 60;
             long minutes = (remainingMillis / (1000 * 60)) % 60;
             String timeString = String.format("%d minutes %d seconds", minutes, seconds);
             
             return ResponseEntity.status(429).body("{\"message\": \"Too many failed attempts. You are temporarily blocked. Try again in " + timeString + ".\"}");
        }

        try {
            // Re-authenticate to verify password
            // We use the username from the current authenticated session to ensure they are verifying *their* password
            String currentUsername = authentication.getName();
            
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(currentUsername, request.getPassword())
            );

            // Success
            bruteForceProtectionService.recordSuccess(clientIp);
            java.util.Map<String, String> response = new java.util.HashMap<>();
            response.put("message", "Password verified");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // Failure
            bruteForceProtectionService.recordFailedAttempt(clientIp);
            java.util.Map<String, String> errorResponse = new java.util.HashMap<>();
            errorResponse.put("message", "Invalid credentials");
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
}
