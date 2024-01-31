package io.github.toquery.example.spring.security.multiple.authentication.bff.filter.controller;

import io.github.toquery.example.spring.security.multiple.authentication.bff.filter.service.FilterService;
import io.github.toquery.example.spring.security.multiple.authentication.core.model.vo.request.LoginRequest;
import io.github.toquery.example.spring.security.multiple.authentication.core.model.vo.response.LoginResponse;
import io.github.toquery.example.spring.security.multiple.authentication.core.utils.AuthenticationUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

/**
 *
 */
@RestController
@RequestMapping("/filter")
public class FilterController {

    @Resource
    private FilterService filterService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(filterService.login(request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(HttpServletRequest request) throws IOException {
        return ResponseEntity.ok(filterService.refreshToken(request));
    }

    @ResponseBody
    @GetMapping(value = {"", "/", "/info", "/index"})
    public Map<String, Object> index(
            Authentication authentication,
//            BearerTokenAuthenticationToken bearerTokenAuthenticationToken,
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken,
            @CurrentSecurityContext(expression = "authentication") UsernamePasswordAuthenticationToken authentication2,
            @CurrentSecurityContext(expression = "authentication.principal") Principal principal2,

            Principal principal,
            @AuthenticationPrincipal Object object,
            @AuthenticationPrincipal User user,
            @AuthenticationPrincipal(expression = "username") String username
//            @AuthenticationPrincipal Jwt jwt,
//            JwtAuthenticationToken jwtAuthenticationToken,
//            @AuthenticationPrincipal OAuth2User oauth2User
    ) {
        Authentication authenticationSecurityContextHolder = SecurityContextHolder.getContext().getAuthentication();
        return AuthenticationUtils.authenticationInfo(this.getClass().getSimpleName(), authentication, principal,null, null);
    }
}
