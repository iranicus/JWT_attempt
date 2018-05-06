package com.rdanby.jwt.security;

import com.rdanby.jwt.db.User;
import com.rdanby.jwt.db.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collections;

/**
 * Handles retrieval of an existing user in the "database" otherwise
 * an exception is thrown.
 *
 * @author richard.j.danby
 * @version 1.0, 05/05/2018
 */
@Component
public class AppUserDetailService implements UserDetailsService {
    private final UserService userService;

    public AppUserDetailService(UserService userService) {
        this.userService = userService;
    }

    /**
     * Instantiates an existing user from the "database" and instantiates a UserDetails.
     * Utilizes the builder from User to create the UserDetails instance.
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException    User wasn't found in the DB
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final User user = this.userService.lookup(username);
        if (user == null) {
            throw new UsernameNotFoundException("User '" + username + "' not found.");
        }

        return org.springframework.security.core.userdetails.User
                .withUsername(username)
                .password(user.getPassword())
                .authorities(Collections.emptyList())
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }
}
