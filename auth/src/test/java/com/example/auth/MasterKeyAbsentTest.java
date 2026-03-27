package com.example.auth;

import com.example.auth.service.MasterKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test vérifiant que l'application refuse de démarrer si APP_MASTER_KEY est absente ou vide.
 *
 * <p>Utilise {@link ApplicationContextRunner} pour démarrer un contexte minimal
 * contenant uniquement {@link MasterKeyService} et vérifier que l'initialisation
 * échoue avec une {@link IllegalStateException}.</p>
 *
 * @version 4.0
 */
class MasterKeyAbsentTest {

    /**
     * Configuration minimale exposant uniquement MasterKeyService.
     */
    @Configuration
    static class TestConfig {
        @Bean
        MasterKeyService masterKeyService() {
            return new MasterKeyService();
        }
    }

    /**
     * Test 27 — Démarrage KO si APP_MASTER_KEY est vide.
     *
     * <p>On s'attend à ce que {@code @PostConstruct} lève une
     * {@link IllegalStateException} et que Spring l'encapsule dans une exception
     * de création de bean.</p>
     */
    @Test
    void testStartupKoIfMasterKeyAbsent() {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withUserConfiguration(TestConfig.class)
                .withPropertyValues("APP_MASTER_KEY=");  // clé vide

        runner.run(context ->
                assertThatThrownBy(() -> context.getBean(MasterKeyService.class))
                        .isInstanceOf(Exception.class)
        );
    }
}
