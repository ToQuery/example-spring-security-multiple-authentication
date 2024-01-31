package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AdminUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RequestMatcherDelegatingAuthenticationManagerResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 *
 */
@Configuration
public class OAuth2AdminSecurityConfig {

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

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> multiAuthenticationManager(
            @Qualifier("openAuthenticationManager") AuthenticationManager openAuthenticationManager,
            @Qualifier("adminAuthenticationManager") AuthenticationManager adminAuthenticationManager
    ) {
        RequestMatcherDelegatingAuthenticationManagerResolver.Builder requestMatcherDelegatingAuthenticationManagerResolverBuilder = RequestMatcherDelegatingAuthenticationManagerResolver.builder();
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(new AntPathRequestMatcher("/admin/**"), adminAuthenticationManager);
        // 处理 /open 认证协议
        requestMatcherDelegatingAuthenticationManagerResolverBuilder.add(new AntPathRequestMatcher("/open/**"), openAuthenticationManager);
        return requestMatcherDelegatingAuthenticationManagerResolverBuilder.build();
    }

    @Bean
    public SecurityFilterChain oauthServerSecurityFilterChain(
            HttpSecurity http,
            BearerTokenResolver bearerTokenResolver,
            AuthenticationManagerResolver<HttpServletRequest> multiClientAuthenticationManager
    ) throws Exception {

        http.securityMatcher("/admin/**", "/open/**");

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers("/admin/**").authenticated();
            authorizationManagerRequestMatcherRegistry.requestMatchers("/open/**").authenticated();
//            authorizationManagerRequestMatcherRegistry.requestMatchers("/open/**").hasAuthority("SCOPE_write");
        });

        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
            httpSecurityOAuth2ResourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
            httpSecurityOAuth2ResourceServerConfigurer.authenticationManagerResolver(multiClientAuthenticationManager);
        });

        return http.build();
    }
}
