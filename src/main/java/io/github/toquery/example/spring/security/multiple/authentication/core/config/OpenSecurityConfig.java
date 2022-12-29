package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

/**
 *
 */
@Configuration
@EnableWebSecurity
public class OpenSecurityConfig {

    @Bean
    public JwtAuthenticationProvider openAuthenticationProvider(JwtDecoder jwtDecoder) {
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        jwtAuthenticationProvider.setJwtAuthenticationConverter(new JwtAuthenticationConverter());
        return jwtAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager openAuthenticationManager(JwtAuthenticationProvider openAuthenticationProvider) {
        return openAuthenticationProvider::authenticate;
    }


}
