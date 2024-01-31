package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AppUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@Configuration
public class OAuth2AppSecurityConfig {

    /**
     * 移动端用户
     */
    @Bean
    public UserDetailsService appUserDetailsService() {
        return new AppUserDetailsService();
    }

    @Bean
    protected AuthenticationProvider appAuthenticationProvider(UserDetailsService appUserDetailsService) {
        DaoAuthenticationProvider appDaoAuthenticationProvider = new DaoAuthenticationProvider();
        appDaoAuthenticationProvider.setUserDetailsService(appUserDetailsService);
        return appDaoAuthenticationProvider;
    }


    @Bean
    public AuthenticationManager appAuthenticationManager(AuthenticationProvider appAuthenticationProvider) {
        return appAuthenticationProvider::authenticate;
    }


    @Bean
    public SecurityFilterChain appServerSecurityFilterChain(
            HttpSecurity http,
            BearerTokenResolver bearerTokenResolver,
            AuthenticationManager appAuthenticationManager
    ) throws Exception {

        http.securityMatcher("/app/**");

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers("/app/**").authenticated();
        });

        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
            httpSecurityOAuth2ResourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
            httpSecurityOAuth2ResourceServerConfigurer.jwt(jwtConfigurer -> {
                jwtConfigurer.authenticationManager(appAuthenticationManager);
            });
        });

        return http.build();
    }
}
