package io.github.toquery.example.spring.security.multiple.authentication.bff.open;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 */
@RestController
@RequestMapping("/open")
public class OpenController {

    @GetMapping(value = {"", "/", "/index"})
    public String index() {
        return "open";
    }
}
