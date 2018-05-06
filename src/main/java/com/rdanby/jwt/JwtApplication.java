package com.rdanby.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.SpringVersion;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * A Java Spring Boot JWT Authentication demonstration with an Ionic 3 front end.
 * The registered users credentials are stored in a in-memory map defined in the UserService, therefore they
 * only exist while the application is running, and are lost when stopped. (Only testing the auth functionality
 * in this project).
 *
 * Followed tutorial: https://golb.hplar.ch/2017/02/JWT-Authentication-with-Ionic-2-and-Spring-Boot.html
 */
@SpringBootApplication
@ComponentScan({"com.rdanby.jwt.security.jwt"})
public class JwtApplication {
	public final static Logger logger = LoggerFactory.getLogger(JwtApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
		// System.out.println("Spring version: " + SpringVersion.getVersion());
		// System.out.println("Spring Boot version: " + SpringBootVersion.getVersion());
		// System.out.println("Spring Security version: " + SpringSecurityCoreVersion.getVersion());
	}

	/**
	 * Encrypts the password from Spring Security that uses
	 * BCrypt grade hashing function. The strength can be supplied
	 * (aka log rounds in BCrypt) and a SecureRandom instance. The larger the strength
	 * the more work needs to be done to hash the password. Default is 10.
	 *
	 * See for info:
	 * https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/
	 * crypto/bcrypt/BCryptPasswordEncoder.html
	 *
	 * @return
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}
}
