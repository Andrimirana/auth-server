package com.example.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Service de calcul et vérification des signatures HMAC-SHA256.
 *
 * <p>Utilisé dans le protocole d'authentification TP3 pour prouver
 * la connaissance du mot de passe sans l'envoyer sur le réseau.</p>
 *
 * <p><b>Important :</b> La comparaison utilise toujours
 * {@link MessageDigest#isEqual} pour éviter les attaques temporelles (timing attacks).</p>
 */
@Service
public class HmacService {

    /**
     * Calcule un HMAC-SHA256 encodé en Base64.
     *
     * @param key  clé secrète (le mot de passe utilisateur)
     * @param data message à signer (email:nonce:timestamp)
     * @return signature HMAC en Base64
     * @throws Exception si l'algorithme HmacSHA256 n'est pas disponible
     */
    public String compute(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"
        );
        mac.init(secretKey);
        byte[] result = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * Compare deux signatures HMAC en temps constant.
     *
     * <p>Empêche les attaques temporelles qui exploitent
     * les différences de temps de comparaison caractère par caractère.</p>
     *
     * @param expected signature attendue
     * @param received signature reçue du client
     * @return true si les deux signatures sont identiques
     */
    public boolean compare(String expected, String received) {
        if (expected == null || received == null) return false;
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                received.getBytes(StandardCharsets.UTF_8)
        );
    }
}