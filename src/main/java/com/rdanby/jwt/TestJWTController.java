package com.rdanby.jwt;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test endpoints that are only accessible with a valid JWT, the front end Home Page will
 * display the responses from these methods upon user login.
 */
@RestController
public class TestJWTController {
    @GetMapping("/public")
    @CrossOrigin
    public String publicService() {
        return "This message is public";
    }

    @GetMapping("/secret")
    @CrossOrigin
    public String secretService() {
        return "A secret message";
    }
}
