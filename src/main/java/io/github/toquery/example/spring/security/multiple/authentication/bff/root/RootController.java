package io.github.toquery.example.spring.security.multiple.authentication.bff.root;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 */
@RestController
@RequestMapping(value = {"", "/root"})
public class RootController {

    @GetMapping(value = {"","/", "/index"})
    public String index(){
        return "root";
    }
}
