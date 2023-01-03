package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@Configuration
public class ResourceSecurityConfig {

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
    public SecurityFilterChain oauth2ResourceServerSecurityFilterChain(
            HttpSecurity http,
            BearerTokenResolver bearerTokenResolver,
            AuthenticationManagerResolver<HttpServletRequest> multiClientAuthenticationManager
    ) throws Exception {


        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
            httpSecurityOAuth2ResourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
            httpSecurityOAuth2ResourceServerConfigurer.authenticationManagerResolver(multiClientAuthenticationManager);
        });

        return http.build();
    }
}
