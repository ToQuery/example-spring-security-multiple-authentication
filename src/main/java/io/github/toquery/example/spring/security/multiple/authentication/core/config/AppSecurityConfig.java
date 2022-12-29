package io.github.toquery.example.spring.security.multiple.authentication.core.config;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails.AppUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 *
 */
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {


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
