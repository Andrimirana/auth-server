package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement/déchiffrement des mots de passe via une Master Key (TP4).
 *
 * <h2>Algorithme utilisé</h2>
 * <p>AES en mode GCM (Galois/Counter Mode) avec un tag d'authentification de 128 bits.
 * Ce mode garantit à la fois la <b>confidentialité</b> et l'<b>intégrité</b> des données.</p>
 *
 * <h2>Format de stockage</h2>
 * <pre>v1:Base64(iv):Base64(ciphertext)</pre>
 * <ul>
 *   <li><b>v1</b> : version du format (permet une migration future)</li>
 *   <li><b>iv</b> : vecteur d'initialisation aléatoire de 12 octets (GCM standard)</li>
 *   <li><b>ciphertext</b> : données chiffrées + tag GCM 128 bits</li>
 * </ul>
 *
 * <h2>Injections obligatoires</h2>
 * <p>La variable d'environnement {@code APP_MASTER_KEY} doit être définie.
 * Si elle est absente ou vide, l'application <b>refuse de démarrer</b>.</p>
 *
 * <h2>Interdictions strictes</h2>
 * <ul>
 *   <li>Pas de clé codée en dur</li>
 *   <li>Pas d'IV fixe — un IV aléatoire est généré à chaque chiffrement</li>
 *   <li>Pas de mode ECB</li>
 *   <li>Ne jamais logger un mot de passe en clair</li>
 * </ul>
 *
 * @version 4.0
 */
@Service
public class MasterKeyService {

    private static final Logger logger = LoggerFactory.getLogger(MasterKeyService.class);

    private static final String       ALGORITHM     = "AES/GCM/NoPadding";
    private static final int          GCM_IV_LENGTH = 12;
    private static final int          GCM_TAG_BITS  = 128;
    private static final String       FORMAT_PREFIX = "v1";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Master Key injectée depuis la variable d'environnement {@code APP_MASTER_KEY}. */
    @Value("${APP_MASTER_KEY}")
    private String masterKeyRaw;

    /** Clé AES-256 dérivée de la Master Key par SHA-256. */
    private SecretKey secretKey;

    /**
     * Initialise et valide la Master Key au démarrage de l'application.
     *
     * <p>Si {@code APP_MASTER_KEY} est absente ou vide, l'application refuse de démarrer
     * en levant une {@link IllegalStateException}.</p>
     *
     * @throws IllegalStateException si la Master Key est absente ou vide
     */
    @PostConstruct
    public void init() {
        if (masterKeyRaw == null || masterKeyRaw.isBlank()) {
            throw new IllegalStateException(
                    "[SÉCURITÉ] APP_MASTER_KEY est absente ou vide. " +
                    "L'application refuse de démarrer sans clé de chiffrement."
            );
        }
        try {
            byte[] keyBytes = MessageDigest.getInstance("SHA-256")
                    .digest(masterKeyRaw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            this.secretKey = new SecretKeySpec(keyBytes, "AES");
            logger.info("MasterKeyService initialisé — chiffrement AES-256-GCM activé.");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Impossible d'initialiser AES-256 : SHA-256 non disponible", e);
        }
    }

    /**
     * Chiffre un mot de passe en clair avec AES-256-GCM.
     *
     * <p>Un IV aléatoire de 12 octets est généré à chaque appel,
     * garantissant qu'un même mot de passe produit un ciphertext différent à chaque fois.</p>
     *
     * @param plaintext le mot de passe en clair à chiffrer
     * @return la chaîne chiffrée au format {@code v1:Base64(iv):Base64(ciphertext)}
     * @throws IllegalArgumentException si le plaintext est null ou vide
     * @throws IllegalStateException    si le chiffrement AES-GCM échoue
     */
    @SuppressWarnings("java:S4787") // Utilisation intentionnelle d'AES-256-GCM — algorithme fort approuvé
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) {
            throw new IllegalArgumentException("Le plaintext ne peut pas être null ou vide");
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

            byte[] ciphertext = cipher.doFinal(
                    plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );

            String ivB64         = Base64.getEncoder().encodeToString(iv);
            String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

            return FORMAT_PREFIX + ":" + ivB64 + ":" + ciphertextB64;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Erreur lors du chiffrement AES-GCM", e);
        }
    }

    /**
     * Déchiffre une valeur stockée au format {@code v1:Base64(iv):Base64(ciphertext)}.
     *
     * <p>Le mode GCM vérifie automatiquement l'intégrité des données.
     * Si le ciphertext a été modifié, une exception est levée.</p>
     *
     * @param stored la valeur chiffrée au format {@code v1:...}
     * @return le mot de passe en clair
     * @throws IllegalArgumentException si le format est invalide ou si l'intégrité GCM échoue
     */
    @SuppressWarnings("java:S4787") // Utilisation intentionnelle d'AES-256-GCM — algorithme fort approuvé
    public String decrypt(String stored) {
        if (stored == null || stored.isBlank()) {
            throw new IllegalArgumentException("La valeur chiffrée ne peut pas être null ou vide");
        }
        String[] parts = stored.split(":");
        if (parts.length != 3 || !FORMAT_PREFIX.equals(parts[0])) {
            throw new IllegalArgumentException(
                    "Format de stockage invalide. Attendu : v1:Base64(iv):Base64(ciphertext)"
            );
        }
        try {
            byte[] iv         = Base64.getDecoder().decode(parts[1]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

            byte[] plainBytes = cipher.doFinal(ciphertext);
            return new String(plainBytes, java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Échec du déchiffrement AES-GCM — données corrompues ou clé incorrecte", e);
        }
    }
}

