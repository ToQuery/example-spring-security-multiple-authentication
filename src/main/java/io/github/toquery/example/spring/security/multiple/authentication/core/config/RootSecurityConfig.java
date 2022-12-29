package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.RootUserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@Configuration
@EnableWebSecurity
public class RootSecurityConfig {

    @Bean
    public UserDetailsService rootUserDetailsService() {
        return new RootUserDetailsService();
    }


    @Bean
    protected AuthenticationProvider rootAuthenticationProvider(
            UserDetailsService rootUserDetailsService
    ) throws Exception {
        DaoAuthenticationProvider rootDaoAuthenticationProvider = new DaoAuthenticationProvider();
        rootDaoAuthenticationProvider.setUserDetailsService(rootUserDetailsService);
        return rootDaoAuthenticationProvider;
    }


    @Bean
    @Primary
    public AuthenticationManager rootAuthenticationManager(AuthenticationProvider rootAuthenticationProvider) {
        return rootAuthenticationProvider::authenticate;
    }

}
