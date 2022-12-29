package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RequestMatcherDelegatingAuthenticationManagerResolver;


/**
 *
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {



    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> multiClientAuthenticationManager(
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

    /**
     * 从request请求中那个地方获取到token
     */
    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
        // 是否可以从uri请求参数中获取token
        bearerTokenResolver.setAllowUriQueryParameter(true);
        bearerTokenResolver.setAllowFormEncodedBodyParameter(true);
        return bearerTokenResolver;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            BearerTokenResolver bearerTokenResolver,
            AuthenticationManagerResolver<HttpServletRequest> multiClientAuthenticationManager
    ) throws Exception {

        http.httpBasic(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers(HttpMethod.OPTIONS).permitAll();
            authorizationManagerRequestMatcherRegistry.requestMatchers("/", "/error", "/login").permitAll();

            authorizationManagerRequestMatcherRegistry.requestMatchers("/root").hasAuthority("ROOT");

            authorizationManagerRequestMatcherRegistry.requestMatchers("/open/**").hasAuthority("SCOPE_write");

        });


        http.oauth2Login(httpSecurityOAuth2LoginConfigurer -> {
        });

        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
            httpSecurityOAuth2ResourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
            httpSecurityOAuth2ResourceServerConfigurer.authenticationManagerResolver(multiClientAuthenticationManager);
        });

        return http.build();
    }


}
