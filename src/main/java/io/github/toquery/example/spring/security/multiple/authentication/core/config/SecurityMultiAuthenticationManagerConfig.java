package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AppUserDetailsService;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.RootUserDetailsService;
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
    public static class AppSecurityConfig {
        /**
         * 移动端用户
         */
        @Bean
        public UserDetailsService appUserDetailsService() {
            return new AppUserDetailsService();
        }

        @Bean
        protected AuthenticationProvider appAuthenticationProvider(
                UserDetailsService appUserDetailsService
        ) throws Exception {
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
    public static class RootSecurityConfig {

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


    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> multiAuthenticationManager(
            AuthenticationManager appAuthenticationManager,
            AuthenticationManager openAuthenticationManager,
            AuthenticationManager rootAuthenticationManager
    ) {
        RequestMatcherDelegatingAuthenticationManagerResolver.Builder requestMatcherDelegatingAuthenticationManagerResolverBuilder = RequestMatcherDelegatingAuthenticationManagerResolver.builder();
        // 处理 /open 认证协议
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/open"), openAuthenticationManager);

        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/root"), rootAuthenticationManager);

        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(request -> request.getRequestURI().startsWith("/app"), appAuthenticationManager);

        return requestMatcherDelegatingAuthenticationManagerResolverBuilder.build();
    }
}
