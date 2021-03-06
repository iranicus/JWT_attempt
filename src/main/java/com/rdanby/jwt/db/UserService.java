package com.rdanby.jwt.db;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles the authorization CRUD operations for the in memory DB.
 */
@Service
public class UserService {
    private final Map<String, User> db;

    public UserService() {
        this.db = new ConcurrentHashMap<>();
    }

    public User lookup(String username) {
        return this.db.get(username);
    }

    public void save(User user) {
        this.db.put(user.getUsername(), user);
    }

    public boolean usernameExists(String username) {
        return this.db.containsKey(username);
    }
}
