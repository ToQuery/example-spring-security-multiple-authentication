package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.filter.JwtAuthenticationFilter;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.handler.AppLogoutHandler;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.FilterUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 *
 */
@Configuration
public class FilterSecurityConfig {


    /**
     *
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

    @Bean
    public SecurityFilterChain filterSecurityFilterChain(
            HttpSecurity http,
            JwtAuthenticationProvider filterAuthenticationProvider,
            JwtAuthenticationFilter jwtAuthFilter,
            AppLogoutHandler logoutHandler
    ) throws Exception {
        http.securityMatcher("/filter/**");

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authenticationProvider(filterAuthenticationProvider);

        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers("/filter/login").permitAll();
            authorizationManagerRequestMatcherRegistry.requestMatchers("/filter/**").authenticated();
            authorizationManagerRequestMatcherRegistry.anyRequest().authenticated();
        });

        http.logout(logout -> {
            logout.logoutUrl("/filter/logout");
            logout.addLogoutHandler(logoutHandler);
            logout.clearAuthentication(true);
            logout.logoutSuccessHandler((request, response, authentication) -> {
                response.setStatus(200);
                response.getWriter().write("Logout Success");
            });
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
