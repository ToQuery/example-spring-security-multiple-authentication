package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;


/**
 *
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http.httpBasic(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers(HttpMethod.OPTIONS).permitAll();
            authorizationManagerRequestMatcherRegistry.requestMatchers("/", "/error", "/login").permitAll();
            authorizationManagerRequestMatcherRegistry.requestMatchers("/app").hasAuthority("ROOT");
            authorizationManagerRequestMatcherRegistry.requestMatchers("/admin").hasAuthority("ROOT");
            authorizationManagerRequestMatcherRegistry.requestMatchers("/open/**").hasAuthority("SCOPE_write");
        });

        return http.build();
    }


}
