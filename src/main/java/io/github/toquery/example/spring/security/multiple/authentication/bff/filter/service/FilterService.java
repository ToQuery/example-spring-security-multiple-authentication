package io.github.toquery.example.spring.security.multiple.authentication.bff.filter.service;


import io.github.toquery.example.spring.security.multiple.authentication.core.model.vo.request.LoginRequest;
import io.github.toquery.example.spring.security.multiple.authentication.core.model.vo.response.LoginResponse;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.token.Token;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.token.TokenJwtService;
import io.github.toquery.example.spring.security.multiple.authentication.core.security.token.TokenRepository;
import io.github.toquery.example.spring.security.multiple.authentication.core.utils.AuthenticationUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class FilterService {
    private final UserDetailsService filterUserDetailsService;
    private final TokenRepository tokenRepository;
    private final TokenJwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public LoginResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        var user = filterUserDetailsService.loadUserByUsername(request.getUsername());
        var jwtToken = jwtService.generateToken(user.getUsername());
        var refreshToken = jwtService.generateRefreshToken(user.getUsername());
        revokeAllUserTokens(user.getUsername());
        saveUserToken(user.getUsername(), jwtToken);
        return LoginResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserToken(String username, String jwtToken) {
        var token = Token.builder()
                .username(username)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.saveOrUpdate(token);
    }

    private void revokeAllUserTokens(String username) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(username);
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveOrUpdate(validUserTokens);
    }

    public LoginResponse refreshToken(HttpServletRequest request) throws IOException {
        String token = AuthenticationUtils.bearerToken(request);
        if (token == null) {
            return null;
        }
        String username = jwtService.extractUsername(token);
        if (username == null) {
            return null;
        }
        var tokenDB = this.tokenRepository.findByUsername(username).orElseThrow();
        if (jwtService.isTokenValid(tokenDB.getToken(), username)) {
            var accessToken = jwtService.generateToken(username);
            var refreshToken = jwtService.generateRefreshToken(username);
            revokeAllUserTokens(username);
            saveUserToken(username, accessToken);
            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        }
        return null;
    }
}
