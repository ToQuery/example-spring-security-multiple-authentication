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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


/**
 *
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class AdminSecurityConfig {

    @Bean
    public SecurityFilterChain adminSecurityFilterChain(
            HttpSecurity http
    ) throws Exception {
        http.securityMatcher("/admin/**");

        http.httpBasic(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
//            authorizationManagerRequestMatcherRegistry.requestMatchers("/", "/error", "/login").permitAll();
//            authorizationManagerRequestMatcherRegistry.requestMatchers("/app").hasAuthority("ROOT");
//            authorizationManagerRequestMatcherRegistry.requestMatchers("/open/**").hasAuthority("SCOPE_write");


            authorizationManagerRequestMatcherRegistry.requestMatchers("/admin/**").authenticated();
        });

        return http.build();
    }


}
