package io.github.toquery.example.spring.security.multiple.authentication.core.security.userdetails;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 *
 */
public class BasicUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.withUsername("basic")
                .password("{noop}123456")
                .roles("BASIC")
                .authorities("BASIC")
                .disabled(false)
                .build();
    }
}
