package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@Configuration
@EnableWebSecurity
public class AdminSecurityConfig {


//    @Bean
//    public AuthenticationManager openAuthenticationManager() {
//        OAuth2LoginAuthenticationToken oAuth2LoginAuthenticationToken = new OAuth2LoginAuthenticationToken();
//        return oAuth2LoginAuthenticationToken;
//    }


}
