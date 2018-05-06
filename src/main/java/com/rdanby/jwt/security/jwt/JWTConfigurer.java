package com.rdanby.jwt.security.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Helper class that adds the JWTFilter into the chain of security filters before the
 * UsernamePasswordAuthenticationFilter in order to check if the Http request contains a valid
 * JWT before presenting the login dialog.
 */

public class JWTConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final TokenProvider tokenProvider;

    public JWTConfigurer(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Adds the JWTFilter (where the Http request is checked for a valid JWT in the header)
     * to ensure the JWT is valid and has been authenticated before allowing the user to access the
     * login dialog.
     *
     * @param http      The secure HTTP request to add the JWTFilter to (authenticates the JWT if present)
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        JWTFilter customFilter = new JWTFilter(this.tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
        System.out.println("JWT Filter added");
    }
}
