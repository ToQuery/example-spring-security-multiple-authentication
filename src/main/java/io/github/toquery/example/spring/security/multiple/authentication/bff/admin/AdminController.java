package io.github.toquery.example.spring.security.multiple.authentication.bff.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping(value = {"","/", "/index"})
    public String index() {
        return "admin";
    }
}
