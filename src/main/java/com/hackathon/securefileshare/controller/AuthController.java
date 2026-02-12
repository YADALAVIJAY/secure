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

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal(); // Cast is important
            String jwt = jwtUtil.generateToken(userDetails.getUsername());

            return ResponseEntity.ok(new AuthResponse(jwt, userDetails.getUsername()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid credentials");
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(Authentication authentication) {
        try {
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            return ResponseEntity.ok(new com.hackathon.securefileshare.dto.UserProfile(
                user.getUsername(),
                user.getEmail(),
                user.getPublicKey(),
                user.getEncryptedPrivateKey()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to fetch profile");
        }
    }
}
