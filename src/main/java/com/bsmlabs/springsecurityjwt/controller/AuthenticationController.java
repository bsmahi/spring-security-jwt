package com.bsmlabs.springsecurityjwt.controller;

import com.bsmlabs.springsecurityjwt.services.JwtTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationController.class);

    private final JwtTokenService jwtTokenService;

    public AuthenticationController(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    @PostMapping("/generate-token")
    public String getToken(Authentication authentication) {
        LOGGER.info("Token requested for user, {}", authentication.getName());
        String token = jwtTokenService.createToken(authentication);
        LOGGER.info("Token Generated, {}", token);

        return token;
    }
}
