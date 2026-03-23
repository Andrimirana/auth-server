package com.example.auth.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement AES-GCM utilisant la Master Key (TP4).
 *
 * <p>Ce service chiffre et déchiffre les mots de passe avant stockage en base.
 * La Master Key est injectée via la variable d'environnement {@code APP_MASTER_KEY}
 * et ne doit JAMAIS être codée en dur dans le code source.</p>
 *
 * <p><b>Format de stockage :</b> {@code v1:Base64(iv):Base64(ciphertext)}</p>
 *
 * <p><b>Note pédagogique TP4 :</b> Ce chiffrement réversible (AES-GCM) est conservé
 * pour permettre le protocole HMAC du TP3. En production industrielle, on préférerait
 * un hash adaptatif non réversible (bcrypt). Ici, on accepte le chiffrement réversible
 * pour permettre l'apprentissage du protocole signé.</p>
 *
 * @author Étudiant CDWFS
 * @version 4.0
 */
@Service
public class MasterKeyEncryptionService {

    private static final String ALGORITHM    = "AES/GCM/NoPadding";
    private static final int    IV_LENGTH    = 12;   // 96 bits — recommandé pour GCM
    private static final int    TAG_LENGTH   = 128;  // bits — tag d'authenticité GCM
    private static final String FORMAT_V1    = "v1";
    // SecureRandom est thread-safe et coûteux à instancier — réutilisé comme champ
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Clé injectée depuis la variable d'environnement APP_MASTER_KEY.
     * Doit être une clé AES-256 encodée en Base64 (32 octets décodés).
     */
    @Value("${app.master.key:#{null}}")
    private String masterKeyBase64;

    private SecretKey secretKey;

    /**
     * Initialise la clé secrète au démarrage de Spring.
     * L'application refuse de démarrer si la clé est absente ou invalide.
     *
     * @throws IllegalStateException si APP_MASTER_KEY est absente, vide ou invalide
     */
    @PostConstruct
    public void init() {
        if (masterKeyBase64 == null || masterKeyBase64.isBlank()) {
            throw new IllegalStateException(
                    "[SÉCURITÉ - TP4] La variable d'environnement APP_MASTER_KEY est absente. " +
                            "L'application refuse de démarrer sans clé de chiffrement. " +
                            "Générer une clé avec : openssl rand -base64 32"
            );
        }

        try {
            byte[] keyBytes = Base64.getDecoder().decode(masterKeyBase64);
            if (keyBytes.length != 32) {
                throw new IllegalStateException(
                        "[SÉCURITÉ - TP4] APP_MASTER_KEY doit être une clé AES-256 " +
                                "encodée en Base64 (32 octets = 256 bits). Longueur reçue : " + keyBytes.length
                );
            }
            this.secretKey = new SecretKeySpec(keyBytes, "AES");
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "[SÉCURITÉ - TP4] APP_MASTER_KEY n'est pas un Base64 valide.", e
            );
        }
    }

    /**
     * Chiffre un texte en clair avec AES-GCM.
     *
     * <p>Un IV (vecteur d'initialisation) aléatoire de 12 octets est généré à chaque appel,
     * garantissant que deux chiffrements du même texte produisent des résultats différents.</p>
     *
     * @param plaintext texte en clair à chiffrer (ex : mot de passe)
     * @return chaîne chiffrée au format {@code v1:Base64(iv):Base64(ciphertext)}
     * @throws RuntimeException si le chiffrement échoue
     */
    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return FORMAT_V1 + ":"
                    + Base64.getEncoder().encodeToString(iv) + ":"
                    + Base64.getEncoder().encodeToString(ciphertext);

        } catch (Exception e) {
            throw new RuntimeException("Erreur lors du chiffrement AES-GCM", e);
        }
    }

    /**
     * Déchiffre une valeur chiffrée au format v1:iv:ciphertext.
     *
     * <p>AES-GCM vérifie automatiquement l'intégrité des données via son tag d'authenticité.
     * Toute modification du ciphertext lève une exception.</p>
     *
     * @param encryptedValue valeur chiffrée au format {@code v1:Base64(iv):Base64(ciphertext)}
     * @return texte en clair déchiffré
     * @throws IllegalArgumentException si le format est invalide
     * @throws RuntimeException         si le déchiffrement échoue (données corrompues ou mauvaise clé)
     */
    public String decrypt(String encryptedValue) {
        if (encryptedValue == null || !encryptedValue.startsWith(FORMAT_V1 + ":")) {
            throw new IllegalArgumentException(
                    "Format de valeur chiffrée invalide. Attendu : v1:Base64(iv):Base64(ciphertext)"
            );
        }

        String[] parts = encryptedValue.split(":", 3);
        if (parts.length != 3) {
            throw new IllegalArgumentException(
                    "Format de valeur chiffrée invalide : 3 parties attendues, reçu : " + parts.length
            );
        }

        try {
            byte[] iv         = Base64.getDecoder().decode(parts[1]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH, iv));

            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException(
                    "Erreur lors du déchiffrement AES-GCM. Données corrompues ou Master Key incorrecte.", e
            );
        }
    }
}