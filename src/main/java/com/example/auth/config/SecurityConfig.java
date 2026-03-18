package com.example.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration Spring Security pour TP3.
 * Désactive la sécurité automatique de Spring pour utiliser
 * notre propre protocole HMAC avec nonce et timestamp.
 *
 * <p><b>NOTE TP3 :</b> Le BCryptPasswordEncoder est supprimé car
 * TP3 utilise HMAC-SHA256 avec le mot de passe en clair comme clé.
 * La protection se fait au niveau du protocole, pas du stockage.</p>
 */
@Configuration
public class SecurityConfig {

    /**
     * Désactive CSRF et ouvre toutes les routes.
     * Notre authentification est gérée via le protocole HMAC + token Bearer.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}