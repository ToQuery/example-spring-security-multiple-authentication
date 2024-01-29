package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AppUserDetailsService;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AdminUserDetailsService;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.FilterUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.authentication.RequestMatcherDelegatingAuthenticationManagerResolver;

/**
 *
 */
@Configuration
public class SecurityMultiAuthenticationManagerConfig {

    @Configuration
    public static class FilterSecurityConfig {
        /**
         * 移动端用户
         */
        @Bean
        public UserDetailsService filterUserDetailsService() {
            return new FilterUserDetailsService();
        }

        @Bean
        protected AuthenticationProvider filterAuthenticationProvider(UserDetailsService filterUserDetailsService) {
            DaoAuthenticationProvider appDaoAuthenticationProvider = new DaoAuthenticationProvider();
            appDaoAuthenticationProvider.setUserDetailsService(filterUserDetailsService);
            return appDaoAuthenticationProvider;
        }


        @Bean
        public AuthenticationManager filterAuthenticationManager(AuthenticationProvider filterAuthenticationProvider) {
            return filterAuthenticationProvider::authenticate;
        }
    }

    @Configuration
    public static class AppSecurityConfig {
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
    }

    @Configuration
    public static class OpenSecurityConfig {

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


    @Configuration
    public static class AdminSecurityConfig {

        @Bean
        public UserDetailsService adminUserDetailsService() {
            return new AdminUserDetailsService();
        }

        @Bean
        protected AuthenticationProvider adminAuthenticationProvider(UserDetailsService adminUserDetailsService) {
            DaoAuthenticationProvider adminDaoAuthenticationProvider = new DaoAuthenticationProvider();
            adminDaoAuthenticationProvider.setUserDetailsService(adminUserDetailsService);
            return adminDaoAuthenticationProvider;
        }

        @Bean
        @Primary
        public AuthenticationManager adminAuthenticationManager(AuthenticationProvider adminAuthenticationProvider) {
            return adminAuthenticationProvider::authenticate;
        }

    }


    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> multiAuthenticationManager(
            AuthenticationManager appAuthenticationManager,
            AuthenticationManager openAuthenticationManager,
            AuthenticationManager adminAuthenticationManager,
            AuthenticationManager filterAuthenticationManager
    ) {
        RequestMatcherDelegatingAuthenticationManagerResolver.Builder requestMatcherDelegatingAuthenticationManagerResolverBuilder = RequestMatcherDelegatingAuthenticationManagerResolver.builder();
        // 处理 /open 认证协议
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/open"), openAuthenticationManager);
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/admin"), adminAuthenticationManager);
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/app"), appAuthenticationManager);
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/filter"), filterAuthenticationManager);

        return requestMatcherDelegatingAuthenticationManagerResolverBuilder.build();
    }
}
