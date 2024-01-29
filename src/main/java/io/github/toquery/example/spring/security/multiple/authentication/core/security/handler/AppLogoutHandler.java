package io.github.toquery.example.spring.security.multiple.authentication.core.security.handler;

import io.github.toquery.example.spring.security.multiple.authentication.core.security.token.TokenRepository;
import io.github.toquery.example.spring.security.multiple.authentication.core.utils.AuthenticationUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AppLogoutHandler implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String jwt = AuthenticationUtils.bearerToken(request);
        if (jwt == null) {
            return;
        }

        var storedToken = tokenRepository.findByToken(jwt).orElse(null);
        if (storedToken != null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.saveOrUpdate(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}
