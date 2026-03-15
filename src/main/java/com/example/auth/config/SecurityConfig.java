package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration Spring Security pour TP2.
 * Désactive la sécurité automatique de Spring pour garder
 * notre propre mécanisme d'authentification maison.
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement
 * fragile et ne doit pas être utilisée en production sans TP3.</p>
 */
@Configuration
public class SecurityConfig {

    /**
     * Désactive CSRF et ouvre toutes les routes.
     * Notre authentification est gérée manuellement via session.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    /**
     * Bean BCrypt utilisé pour hacher les mots de passe.
     * Remplace le stockage en clair du TP1.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}