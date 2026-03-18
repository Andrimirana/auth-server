package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller REST pour les routes protégées par token SSO.
 */
@RestController
@RequestMapping("/api")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Route protégée — accessible uniquement avec un token Bearer valide.
     * GET /api/me
     * Header : Authorization: Bearer token
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new com.example.auth.exception.AuthenticationFailedException(
                    "Token manquant. Utilisez : Authorization: Bearer <token>"
            );
        }

        String tokenValue = authHeader.substring(7);
        User user = authService.getUserByToken(tokenValue);

        return ResponseEntity.ok(Map.of(
                "message", "Accès autorisé",
                "email", user.getEmail()
        ));
    }
}