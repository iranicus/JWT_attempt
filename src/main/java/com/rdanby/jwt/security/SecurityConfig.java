package com.rdanby.jwt.security;

import com.rdanby.jwt.security.jwt.JWTConfigurer;
import com.rdanby.jwt.security.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * @author richard.j.danby
 * @version 1.0, 05/05/2018
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    public SecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Disables CSRF, enables CORS handling, sets the session creation policy to STATELESS to prevent
     * Spring Security from creating non secure HttpSessions.
     *
     * The http endpoints:
     *      /signup     /login      /public
     * are accessible without an authentication, All other endpoints are secure and require a valid JWT token.
     *
     * At the end the JWTConfigurer helper class injects the JWTFilter into the Spring Security filter chain
     * prompting the JWT authentication for the protected routes.
     *
     * @param http          Incoming Http request
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // .httpBasic().and() //optional, if the service wants to be accessed via the browser
                .authorizeRequests()
                    // endPoint configuration requiring authorization
                    .antMatchers("/signup").permitAll()
                    .antMatchers("/login").permitAll()
                    .antMatchers("/public").permitAll()
                    .anyRequest().authenticated().and()
                .apply(new JWTConfigurer(this.tokenProvider));
    }

    // No change in CORS issue when added
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        System.out.println("CORS CONFIGURATION LOADED");
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList("*"));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(Arrays.asList("authorization", "content-type", "x-auth-token"));
//        configuration.setExposedHeaders(Arrays.asList("x-auth-token"));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }
}
