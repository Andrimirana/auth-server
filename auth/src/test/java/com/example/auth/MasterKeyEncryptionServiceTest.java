package com.example.auth;

import com.example.auth.service.MasterKeyEncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests obligatoires TP4 pour MasterKeyEncryptionService.
 *
 * <p>Couvre les 4 cas exigés par le sujet :</p>
 * <ol>
 *   <li>Démarrage KO si APP_MASTER_KEY absente</li>
 *   <li>Chiffrement/Déchiffrement OK (round-trip)</li>
 *   <li>Chiffré ≠ clair</li>
 *   <li>Déchiffrement KO si ciphertext modifié</li>
 * </ol>
 *
 * <p>Ces tests n'utilisent PAS @SpringBootTest pour rester unitaires et rapides.
 * ReflectionTestUtils injecte la clé de test directement sans Spring context.</p>
 */
class MasterKeyEncryptionServiceTest {

    private MasterKeyEncryptionService service;

    // Clé AES-256 de test : 32 octets de zéros encodés en Base64
    // NE JAMAIS utiliser une telle clé en production !
    private static final String TEST_KEY =
            Base64.getEncoder().encodeToString(new byte[32]);

    @BeforeEach
    void setUp() {
        service = new MasterKeyEncryptionService();
        ReflectionTestUtils.setField(service, "masterKeyBase64", TEST_KEY);
        service.init();
    }

    // ─── 1. Démarrage KO si APP_MASTER_KEY absente ────────────────────────

    @Test
    @DisplayName("TP4 - Démarrage KO si APP_MASTER_KEY est null")
    void testDemarrageKoSiCleNull() {
        MasterKeyEncryptionService svc = new MasterKeyEncryptionService();
        ReflectionTestUtils.setField(svc, "masterKeyBase64", null);

        IllegalStateException ex = assertThrows(IllegalStateException.class, svc::init);
        assertTrue(ex.getMessage().contains("APP_MASTER_KEY"),
                "Le message doit mentionner APP_MASTER_KEY");
    }

    @Test
    @DisplayName("TP4 - Démarrage KO si APP_MASTER_KEY est vide")
    void testDemarrageKoSiCleVide() {
        MasterKeyEncryptionService svc = new MasterKeyEncryptionService();
        ReflectionTestUtils.setField(svc, "masterKeyBase64", "   ");

        assertThrows(IllegalStateException.class, svc::init);
    }

    @Test
    @DisplayName("TP4 - Démarrage KO si clé n'est pas 32 octets (AES-256)")
    void testDemarrageKoSiCleTropCourte() {
        MasterKeyEncryptionService svc = new MasterKeyEncryptionService();
        // AES-128 = 16 octets, mais on exige AES-256 = 32 octets
        ReflectionTestUtils.setField(svc,
                "masterKeyBase64",
                Base64.getEncoder().encodeToString(new byte[16])
        );

        IllegalStateException ex = assertThrows(IllegalStateException.class, svc::init);
        assertTrue(ex.getMessage().contains("32 octets"));
    }

    // ─── 2. Chiffrement / Déchiffrement OK ───────────────────────────────

    @Test
    @DisplayName("TP4 - encrypt puis decrypt retourne le texte original")
    void testEncryptDecryptRoundTrip() {
        String original = "MonMotDePasse@Secure123";

        String encrypted = service.encrypt(original);
        String decrypted = service.decrypt(encrypted);

        assertEquals(original, decrypted,
                "Le déchiffrement doit retourner exactement le texte original");
    }

    @Test
    @DisplayName("TP4 - Le format chiffré respecte v1:iv:ciphertext")
    void testFormatChiffreV1() {
        String encrypted = service.encrypt("TestPass@123");

        assertTrue(encrypted.startsWith("v1:"),
                "Le format doit commencer par 'v1:'");

        String[] parts = encrypted.split(":", 3);
        assertEquals(3, parts.length,
                "Le format doit contenir exactement 3 parties séparées par ':'");
        assertFalse(parts[1].isEmpty(), "L'IV ne doit pas être vide");
        assertFalse(parts[2].isEmpty(), "Le ciphertext ne doit pas être vide");
    }

    // ─── 3. Chiffré ≠ Clair ──────────────────────────────────────────────

    @Test
    @DisplayName("TP4 - La valeur chiffrée est différente du mot de passe clair")
    void testChiffreDifferentDuClair() {
        String password  = "MonMotDePasse@Secure123";
        String encrypted = service.encrypt(password);

        assertNotEquals(password, encrypted,
                "La valeur chiffrée ne doit jamais être identique au texte clair");
        assertFalse(encrypted.contains(password),
                "Le mot de passe clair ne doit pas apparaître dans le chiffré");
    }

    @Test
    @DisplayName("TP4 - Deux chiffrements du même texte donnent des résultats différents (IV aléatoire)")
    void testIvAleatoire() {
        String password   = "MonMotDePasse@Secure123";
        String encrypted1 = service.encrypt(password);
        String encrypted2 = service.encrypt(password);

        assertNotEquals(encrypted1, encrypted2,
                "Chaque chiffrement doit produire un résultat différent grâce à l'IV aléatoire");
    }

    // ─── 4. Déchiffrement KO si ciphertext modifié ───────────────────────

    @Test
    @DisplayName("TP4 - Déchiffrement KO si le ciphertext est altéré")
    void testDechiffrementKoSiCiphertextModifie() {
        String encrypted = service.encrypt("MonMotDePasse@Secure123");

        // Altérer le dernier caractère du ciphertext
        String altered = encrypted.substring(0, encrypted.length() - 1) + "X";

        assertThrows(RuntimeException.class, () -> service.decrypt(altered),
                "AES-GCM doit détecter la modification et lever une exception");
    }

    @Test
    @DisplayName("TP4 - Déchiffrement KO si format invalide (sans préfixe v1:)")
    void testDechiffrementKoFormatInvalide() {
        assertThrows(IllegalArgumentException.class,
                () -> service.decrypt("format_completement_invalide"));
    }

    @Test
    @DisplayName("TP4 - Déchiffrement KO si valeur null")
    void testDechiffrementKoNull() {
        assertThrows(IllegalArgumentException.class,
                () -> service.decrypt(null));
    }
}