package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

/**
 * Point d'entrée principal du serveur d'authentification.
 *
 * <p>Application Spring Boot REST stateless implémentant progressivement
 * un protocole d'authentification sécurisé (TP1 → TP3) :</p>
 * <ul>
 *   <li><b>TP1</b> : authentification dangereuse (mot de passe en clair).</li>
 *   <li><b>TP2</b> : hash BCrypt + politique de mot de passe + anti brute-force.</li>
 *   <li><b>TP3</b> : protocole HMAC-SHA256 avec nonce et timestamp (anti-rejeu).</li>
 * </ul>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est à vocation pédagogique.
 * Elle ne doit jamais être utilisée telle quelle en production.</p>
 *
 * @see com.example.auth.controller.AuthController
 * @see com.example.auth.service.AuthService
 * @version 3.0
 */
@SpringBootApplication(exclude = { UserDetailsServiceAutoConfiguration.class })
public class AuthApplication {

    /**
     * Lance l'application Spring Boot.
     *
     * @param args arguments de ligne de commande (non utilisés)
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
