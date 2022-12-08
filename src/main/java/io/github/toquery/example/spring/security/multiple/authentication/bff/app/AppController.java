package io.github.toquery.example.spring.security.multiple.authentication.bff.app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 */
@RestController
@RequestMapping("/app")
public class AppController {
    @GetMapping(value = {"","/", "/index"})
    public String index() {
        return "app";
    }
}
