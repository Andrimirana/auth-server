package com.example.auth.repository;

import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

/**
 * Repository Spring Data JPA pour l'accès aux utilisateurs en base de données.
 *
 * <p>Fournit les opérations CRUD standard héritées de {@link JpaRepository}
 * ainsi que la recherche par email utilisée lors de l'inscription et du login.</p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.</p>
 *
 * @see com.example.auth.entity.User
 * @see com.example.auth.service.AuthService
 * @version 3.0
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Recherche un utilisateur par son adresse email.
     *
     * <p>Utilisé lors de l'inscription (vérification de doublon) et
     * lors du login (chargement pour recalcul HMAC).</p>
     *
     * @param email adresse email à rechercher
     * @return un {@link Optional} contenant l'utilisateur si trouvé, vide sinon
     */
    Optional<User> findByEmail(String email);
}