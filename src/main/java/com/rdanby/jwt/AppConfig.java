package com.rdanby.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author richard.j.danby
 * @version 1.0, 05/05/2018
 */
@ConfigurationProperties(prefix = "app")
@Component
public class AppConfig {
    private String secret;
    private long tokenValidityInSeconds;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getTokenValidityInSeconds() {
        return tokenValidityInSeconds;
    }

    public void setTokenValidityInSeconds(long tokenValidityInSeconds) {
        this.tokenValidityInSeconds = tokenValidityInSeconds;
    }
}
