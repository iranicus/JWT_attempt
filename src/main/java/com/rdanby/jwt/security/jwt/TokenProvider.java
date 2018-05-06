package com.rdanby.jwt.security.jwt;

import com.rdanby.jwt.AppConfig;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Provides functionality for JWT token generation, parse and return an Authentication
 * object to the front end.
 *
 * @author richard.j.danby
 * @version 1.0, 05/05/2018
 */
public class TokenProvider {
    private final String secretKey;
    private final long tokenValidityInMilliseconds;
    private final UserDetailsService userService;

    public TokenProvider(AppConfig config, UserDetailsService userService) {
        this.secretKey = Base64.getEncoder().encodeToString(config.getSecret().getBytes());
        this.tokenValidityInMilliseconds = 1000 * config.getTokenValidityInSeconds();
        this.userService = userService;
    }

    /**
     * Creates a new JWT using the found users username.
     * Generated from the JWT library, needs to know the algorithm (SHA-512) and a secret key, this is
     * read by the application from the application.properties.yml file. It has to be a base64 encoded string.
     *
     * setExpiration    -   Sets the date until the token is valid
     * setIssuedAt      -   Sets the current date and time
     * setSubject       -   Puts the users username into the JWT Subject
     * compact          -   Builds the JWT and returns it as a String
     *
     * @param username  The user's username
     * @return          Generated JWT string
     */
    public String createToken(String username) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + this.tokenValidityInMilliseconds);

        return Jwts.builder().setId(UUID.randomUUID().toString()).setSubject(username).setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS512, this.secretKey).setExpiration(validity).compact();
    }

    /**
     * Parses the JWT, using the same secret key as used in the JWT creation to check validity of the signature
     * if it succeeds the username we stashed in the subject is extracted and the UserDetails is loaded from
     * the "database".
     *
     * @param jwt   The JWT string
     * @return      Authenticated JWT
     */
    public Authentication getAuthentication(String jwt) {
        // retrieve the username from the jwt subject
        String username = Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(jwt).getBody().getSubject();

        // retrieve the users details from the DB with the parsed username from the JWT
        UserDetails userDetails = this.userService.loadUserByUsername(username);

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }
}
