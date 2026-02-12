package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.dto.AuthRequest;
import com.hackathon.securefileshare.dto.AuthResponse;
import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.security.JwtUtil;
import com.hackathon.securefileshare.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        try {
            // Validate input
            if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Username is required\"}");
            }
            if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Email is required\"}");
            }
            if (request.getPassword() == null || request.getPassword().length() < 6) {
                return ResponseEntity.badRequest()
                    .header("Content-Type", "application/json")
                    .body("{\"message\": \"Password must be at least 6 characters\"}");
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

    @Autowired
    private com.hackathon.securefileshare.service.BruteForceProtectionService bruteForceProtectionService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request, jakarta.servlet.http.HttpServletRequest httpRequest) {
        String clientIp = getClientIp(httpRequest);
        System.out.println("DEBUG: Login attempt from IP: " + clientIp);

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
