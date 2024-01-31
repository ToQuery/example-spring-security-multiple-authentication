package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.BasicUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@Configuration
public class BasicSecurityConfig {

    /**
     *
     */
    @Bean
    public UserDetailsService basicUserDetailsService() {
        return new BasicUserDetailsService();
    }

    @Bean
    protected AuthenticationProvider basicAuthenticationProvider(UserDetailsService basicUserDetailsService) {
        DaoAuthenticationProvider basicDaoAuthenticationProvider = new DaoAuthenticationProvider();
        basicDaoAuthenticationProvider.setUserDetailsService(basicUserDetailsService);
        return basicDaoAuthenticationProvider;
    }


    @Bean
    public AuthenticationManager basicAuthenticationManager(AuthenticationProvider basicAuthenticationProvider) {
        return basicAuthenticationProvider::authenticate;
    }

    @Bean
    public SecurityFilterChain basicSecurityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http.securityMatcher("/basic/**");

        http.csrf(AbstractHttpConfigurer::disable);

        http.httpBasic(httpSecurityHttpBasicConfigurer -> {
        });

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers("/basic/**").authenticated();
        });

        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
            httpSecurityExceptionHandlingConfigurer.defaultAccessDeniedHandlerFor((request, response, accessDeniedException) -> {
                response.setStatus(403);
                response.getWriter().write("Access Denied");
            }, (request) -> true);
            httpSecurityExceptionHandlingConfigurer.accessDeniedHandler((request, response, accessDeniedException) -> {
                response.setStatus(403);
                response.getWriter().write("Access Denied");
            });

            httpSecurityExceptionHandlingConfigurer.defaultAuthenticationEntryPointFor((request, response, authException) -> {
                response.setStatus(401);
                response.getWriter().write("Unauthorized");
            }, (request) -> true);
            httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint((request, response, authException) -> {
                response.setStatus(401);
                response.getWriter().write("Unauthorized");
            });

            httpSecurityExceptionHandlingConfigurer.accessDeniedPage("/filter/access-denied");
        });

        return http.build();
    }
}
