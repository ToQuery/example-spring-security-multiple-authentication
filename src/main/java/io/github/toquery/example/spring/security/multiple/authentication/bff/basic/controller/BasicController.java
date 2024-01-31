package io.github.toquery.example.spring.security.multiple.authentication.bff.basic.controller;

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
@RequestMapping("/basic")
public class BasicController {

    @ResponseBody
    @GetMapping(value = {"", "/", "/info", "/index"})
    public Map<String, Object> index(
            Authentication authentication,
            Principal principal
    ) {
        return AuthenticationUtils.authenticationInfo(this.getClass().getSimpleName(), authentication, principal,null, null);
    }
}
