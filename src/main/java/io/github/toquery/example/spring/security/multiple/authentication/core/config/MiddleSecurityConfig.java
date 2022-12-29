package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.provider.RootAuthenticationProvider;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AppUserDetailsService;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.MiddleUserDetailsService;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.RootUserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
//@Configuration
//@EnableWebSecurity
//public class MiddleSecurityConfig {
//
//
//    /**
//     * 中台用户
//     */
//    @Bean
//    public UserDetailsService middleUserDetailsService() {
//        return new MiddleUserDetailsService();
//    }
//
//
//
//
//    @Bean
//    protected AuthenticationProvider middleAuthenticationProvider(
//            UserDetailsService middleUserDetailsService
//    ) throws Exception {
//
//        DaoAuthenticationProvider middleDaoAuthenticationProvider = new DaoAuthenticationProvider();
//        middleDaoAuthenticationProvider.setUserDetailsService(middleUserDetailsService);
//
//        return middleDaoAuthenticationProvider;
//    }
//
//    @Bean
//    public SecurityFilterChain middleSecurityFilterChain(
//            HttpSecurity http,
//            AuthenticationProvider middleAuthenticationProvider
//    ) throws Exception {
//
//        http.httpBasic();
//
//        http.authenticationProvider(middleAuthenticationProvider);
//
//        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//
//        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
//            authorizationManagerRequestMatcherRegistry.requestMatchers("/middle**").hasAuthority("MIDDLE");
//
//        });
//
//
//        return http.build();
//    }
//
//
//}
