package com.rdanby.jwt.security.jwt;

import com.rdanby.jwt.JwtApplication;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *  Filters incoming HTTP requests and installs a Spring Security principal if a header corresponding
 *  to a valid user is found.
 */
public class JWTFilter extends GenericFilterBean {
    public final static String AUTHORIZATION_HEADER = "Authorization";
    private final TokenProvider tokenProvider;

    public JWTFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Checks every HTTP request that needs to be authenticated for the presence of the string JWT in the
     * request header, then authenticate the JWT once parsed with checking the DB if the username extracted
     * from the JWT subject exists.
     *
     * @param servletRequest    Incoming HTTP Request to authenticate
     * @param servletResponse   Outgoing Response after JWT authentication
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        try {
            HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
            // Try retrieve the JWT from the request header if present
            String jwt = resolveToken(httpServletRequest);
            if (jwt != null) {
                // token found in header, authenticate the jwt (Extracts username in subject, checks DB for existence)
                Authentication authentication = this.tokenProvider.getAuthentication(jwt);
                if (authentication != null) {
                    // authentication successful, make the authenticated HTTP request available to rest of the app
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (ExpiredJwtException | UnsupportedJwtException |
                MalformedJwtException | SignatureException | UsernameNotFoundException e) {
            // Not authorised, return appropriate 401 response
            JwtApplication.logger.info("Security exception {}", e.getMessage());
            ((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Checks the HTTP request header for the JWT which should be defined
     * in the Authorization parameter after the Bearer value, for example:
     *      Authorization: Bearer *JWT string*
     *
     * Returns the JWT string value if found.
     *
     * @param req   Incoming request
     * @return      The JWT string
     */
    private static String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader(AUTHORIZATION_HEADER);
        if ((StringUtils.hasText(bearerToken)) && (bearerToken.startsWith("Bearer "))) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
