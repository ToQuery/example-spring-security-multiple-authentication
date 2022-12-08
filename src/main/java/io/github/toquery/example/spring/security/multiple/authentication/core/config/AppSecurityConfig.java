package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.provider.RootAuthenticationProvider;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.RootUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

    @Bean
    public UserDetailsService rootUserDetailsService() {
        return new RootUserDetailsService();
    }

    @Bean
    public UserDetailsService openUserDetailsService() {
        UserDetails user = User.withUsername("open")
                .password("{noop}123456")
                .roles("OPEN")
                .authorities("OPEN")
                .disabled(false)
                .build();
        return new InMemoryUserDetailsManager(user);
    }


    @Bean
    public UserDetailsService adminUserDetailsService() {
        UserDetails user = User.withUsername("admin")
                .password("{noop}123456")
                .roles("ADMIN")
                .authorities("ADMIN")
                .disabled(false)
                .build();
        return new InMemoryUserDetailsManager(user);
    }


    @Bean
    public UserDetailsService appUserDetailsService() {
        UserDetails user = User.withUsername("app")
                .password("{noop}123456")
                .roles("APP")
                .authorities("APP")
                .disabled(false)
                .build();
        return new InMemoryUserDetailsManager(user);
    }


//    @Bean
//    public AuthenticationProvider baseAuthenticationProvider() {
//        return new BaseAuthenticationProvider();
//    }
//
//    @Bean
//    public AuthenticationProvider adminAuthenticationProvider() {
//        return new AdminAuthenticationProvider();
//    }
//    @Bean
//    public AuthenticationProvider appAuthenticationProvider() {
//        return new AppAuthenticationProvider();
//    }
//
//    @Bean
//    public AuthenticationProvider openAuthenticationProvider() {
//        return new OpenAuthenticationProvider();
//    }

    @Bean
    protected AuthenticationManager authenticationManager(
            UserDetailsService adminUserDetailsService,
            UserDetailsService appUserDetailsService,
            UserDetailsService rootUserDetailsService,
            UserDetailsService openUserDetailsService
//            AuthenticationProvider baseAuthenticationProvider,
//            AuthenticationProvider adminAuthenticationProvider,
//            AuthenticationProvider appAuthenticationProvider,
//            AuthenticationProvider openAuthenticationProvider
    ) throws Exception {

        DaoAuthenticationProvider adminDaoAuthenticationProvider = new DaoAuthenticationProvider();
        adminDaoAuthenticationProvider.setUserDetailsService(adminUserDetailsService);

        DaoAuthenticationProvider appDaoAuthenticationProvider = new DaoAuthenticationProvider();
        appDaoAuthenticationProvider.setUserDetailsService(appUserDetailsService);

        RootAuthenticationProvider rootDaoAuthenticationProvider = new RootAuthenticationProvider(rootUserDetailsService);

        DaoAuthenticationProvider openDaoAuthenticationProvider = new DaoAuthenticationProvider();
        openDaoAuthenticationProvider.setUserDetailsService(openUserDetailsService);

        return new ProviderManager(adminDaoAuthenticationProvider, appDaoAuthenticationProvider, rootDaoAuthenticationProvider, openDaoAuthenticationProvider);
    }

    @Bean
    public SecurityFilterChain rootSecurityFilterChain(
            HttpSecurity http
//            AuthenticationManager rootAuthenticationManager
//            AuthenticationProvider baseAuthenticationProvider,
//            AuthenticationProvider openAuthenticationProvider
    ) throws Exception {

        http.httpBasic();

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers(HttpMethod.OPTIONS).permitAll();

            authorizationManagerRequestMatcherRegistry.requestMatchers("/", "/error").permitAll();


            authorizationManagerRequestMatcherRegistry.requestMatchers("/index").hasAuthority("ROOT");
            authorizationManagerRequestMatcherRegistry.requestMatchers("/admin**").hasAuthority("ADMIN");
            authorizationManagerRequestMatcherRegistry.requestMatchers("/app**").hasAuthority("APP");
            authorizationManagerRequestMatcherRegistry.requestMatchers("/open**").hasAuthority("OPEN");
        });

        return http.build();
    }


}
