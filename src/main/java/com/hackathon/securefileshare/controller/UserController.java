package com.hackathon.securefileshare.controller;

import com.hackathon.securefileshare.model.User;
import com.hackathon.securefileshare.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/{username}/public-key")
    public ResponseEntity<?> getUserPublicKey(@PathVariable String username) {
        try {
            User user = userService.findByUsername(username);
            Map<String, String> response = new HashMap<>();
            response.put("username", user.getUsername());
            response.put("publicKey", user.getPublicKey());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("{\"message\": \"User not found\"}");
        }
    }
}
