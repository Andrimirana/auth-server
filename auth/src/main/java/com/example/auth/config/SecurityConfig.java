package com.example.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Configuration Spring Security pour TP3/TP4.
 *
 * <p>Cette API REST stateless utilise son propre protocole d'authentification HMAC-SHA256
 * avec nonce et timestamp. CSRF est désactivé intentionnellement car :</p>
 * <ul>
 *   <li>L'API est stateless (pas de session, pas de cookie de session)</li>
 *   <li>L'authentification passe par un token Bearer dans l'en-tête Authorization</li>
 *   <li>La protection anti-rejeu est assurée par le nonce et la fenêtre de timestamp</li>
 * </ul>
 *
 * <p>Les en-têtes de sécurité HTTP sont activés pour protéger les clients.</p>
 *
 * @see com.example.auth.service.AuthService
 * @see com.example.auth.service.TokenService
 * @version 3.0
 */
@Configuration
public class SecurityConfig {

    /**
     * Configure la chaîne de filtres de sécurité Spring Security.
     *
     * <p>Décisions de configuration :</p>
     * <ul>
     *   <li><b>CSRF désactivé</b> intentionnellement : l'API est stateless,
     *       aucune session ni cookie de session n'est utilisé. La protection
     *       anti-rejeu est assurée par le nonce + fenêtre de timestamp du protocole HMAC.</li>
     *   <li><b>Stateless</b> : aucune session HTTP créée ({@code STATELESS}).</li>
     *   <li><b>En-têtes sécurité</b> : HSTS, X-Content-Type-Options,
     *       X-Frame-Options (DENY), Referrer-Policy.</li>
     *   <li><b>Autorisation ouverte</b> : toutes les routes sont accessibles ;
     *       l'authentification est gérée par notre propre logique dans
     *       {@link com.example.auth.service.AuthService} et
     *       {@link com.example.auth.service.TokenService}.</li>
     * </ul>
     *
     * @param http objet de configuration Spring Security
     * @return la chaîne de filtres configurée
     * @throws Exception si la configuration échoue
     */
    @Bean
    @SuppressWarnings("java:S4502") // CSRF désactivé intentionnellement : API REST stateless (sans session ni cookie).
                                    // La protection anti-rejeu est assurée par le protocole HMAC-SHA256 + nonce + fenêtre de timestamp.
                                    // Aucun formulaire HTML ni cookie de session : le vecteur d'attaque CSRF ne s'applique pas.
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF désactivé intentionnellement : API REST stateless (pas de session/cookie)
                // La protection anti-rejeu est gérée par le protocole HMAC + nonce + timestamp
                .csrf(AbstractHttpConfigurer::disable)

                // API stateless : aucune session HTTP créée
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // En-têtes de sécurité HTTP
                .headers(headers -> headers
                        .contentTypeOptions(contentType -> {})
                        .frameOptions(frame -> frame.deny())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000))
                        .referrerPolicy(referrer ->
                                referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                )

                // Toutes les routes sont accessibles : l'authentification est gérée par
                // notre propre protocole HMAC + token Bearer dans AuthService/TokenService
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        return http.build();
    }
}

