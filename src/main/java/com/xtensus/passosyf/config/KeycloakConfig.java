package com.xtensus.passosyf.config;

import com.xtensus.passosyf.web.rest.AuthorizationAspect;
import com.xtensus.passosyf.web.rest.AuthorizationStatus;
import com.xtensus.passosyf.web.rest.UserController;
import org.keycloak.admin.client.Keycloak;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class KeycloakConfig {

    @Bean
    public Keycloak keycloak() {
        // Create and configure a Keycloak instance
        return Keycloak.getInstance("http://localhost:9080/auth", "google", "admin", "admin", "youtube");
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public AuthorizationStatus authorizationStatus() {
        return new AuthorizationStatus();
    }
}
