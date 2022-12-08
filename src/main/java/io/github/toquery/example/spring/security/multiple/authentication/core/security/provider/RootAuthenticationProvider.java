package io.github.toquery.example.spring.security.multiple.authentication.core.security.provider;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 *
 */
public class RootAuthenticationProvider extends DaoAuthenticationProvider {

    private final UserDetailsService baseUserDetailsService;

    public RootAuthenticationProvider(UserDetailsService baseUserDetailsService) {
        this.baseUserDetailsService = baseUserDetailsService;
        this.setUserDetailsService(baseUserDetailsService);
    }
}
