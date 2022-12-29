package io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 *
 */
public class AppUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.withUsername("app")
                .password("{noop}123456")
                .roles("APP")
                .authorities("APP")
                .disabled(false)
                .build();
    }
}
