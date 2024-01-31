package io.github.toquery.example.spring.security.multiple.authentication.bff.app.controller;

import io.github.toquery.example.spring.security.multiple.authentication.core.utils.AuthenticationUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

/**
 *
 */
@RestController
@RequestMapping("/app")
public class AppController {
    @ResponseBody
    @GetMapping(value = {"", "/", "/info", "/index"})
    public Map<String, Object> index(
            Authentication authentication,
            Principal principal
//            @AuthenticationPrincipal OAuth2User oauth2User,
//            @RegisteredOAuth2AuthorizedClient("example-spring-authorization-server") OAuth2AuthorizedClient authorizedClient
    ) {
        return AuthenticationUtils.authenticationInfo(this.getClass().getSimpleName(), authentication, principal, null, null);
    }
}
