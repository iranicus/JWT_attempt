package com.rdanby.jwt;

import com.rdanby.jwt.db.User;
import com.rdanby.jwt.db.UserService;
import com.rdanby.jwt.security.jwt.TokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

/**
 * The endpoints that the front end targets for various authorization actions.
 */
@RestController
@CrossOrigin
public class AuthController {
   private final UserService userService;
   private final TokenProvider tokenProvider;
   private final PasswordEncoder passwordEncoder;
   private final AuthenticationManager authenticationManager;

    public AuthController(UserService userService, TokenProvider tokenProvider, PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.tokenProvider = tokenProvider;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;

        User user = new User();
        user.setUsername("admin");
        user.setPassword(this.passwordEncoder.encode("admin"));
        this.userService.save(user);
    }

    @GetMapping("/authenticate")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void authenticate() {
        System.out.println("Authenticate Detected");
        // no actions required, this is a secure endPoint where the JWTFilter
        // validates the token, it is called at the startup of the app to check if
        // the JWT is still valid
    }

    /**
     * Signs the new user up if their credentials don't already match an
     * existing users details in the in-memory DB while returning a new JWT string
     * to the front end.
     *
     * @param signupUser    The "new" users credentials
     * @return              New JWT string upon new user signup success
     */
    @PostMapping("/signup")
    public String signup(@RequestBody User signupUser) {
        System.out.println("Signup Detected");
        // ensure user doesn't already have an account
        if (this.userService.usernameExists(signupUser.getUsername())) {
            return "EXISTS";
        }

        // ...otherwise sign the user up starting with replacing the supplied password with an encoded version
        signupUser.encodePassword(this.passwordEncoder);
        // save the new user to the in-memory DB
        this.userService.save(signupUser);
        // return a newly generated JWT to the front end
        return this.tokenProvider.createToken(signupUser.getUsername());
    }

    /**
     * Attempts to log in users who already has an account in the application but the JWT has either expired
     * or they log in with a different device that doesn't have the JWT token stored locally.
     *
     * @param loginUser         Details of the person logging in
     * @param response          Http response returned elsewhere from login attempt
     * @return string | null    Authenticated JWT string otherwise null if auth failed
     */
    @PostMapping("/login")
    public String authorize(@Valid @RequestBody User loginUser, HttpServletResponse response) {
        // System.out.println("Login Detected");
        JwtApplication.logger.info("Login Detected");
        // initialise a new authentication token comprised of the users username and password to validate
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
          loginUser.getUsername(), loginUser.getPassword()
        );

        try {
            // Attempt to authenticate the user's JWT if present with the supplied username and password
            this.authenticationManager.authenticate(authenticationToken);
            // return a new authenticated token if auth succeeded
            return tokenProvider.createToken(loginUser.getUsername());
        } catch (AuthenticationException e) {
            // JWT authentication failed
            System.out.println("UNAUTHORISED LOGIN");
            JwtApplication.logger.info("Security exception {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        }
    }
}
