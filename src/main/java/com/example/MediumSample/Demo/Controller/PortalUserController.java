package com.example.MediumSample.Demo.Controller;

import com.example.MediumSample.Demo.Security.JwtConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class PortalUserController {

    private final JwtConverter jwtConverter;

    public PortalUserController(JwtConverter jwtConverter) {
        this.jwtConverter = jwtConverter;
    }

    @GetMapping("/user-info")
    public Map<String, Object> getUserInfo(JwtAuthenticationToken token) {
        Jwt jwt = token.getToken();
        boolean isTokenValid = jwtConverter.verifyToken(jwt.getTokenValue());

        return Map.of(
                "name", jwt.getClaim("name"),
                "preferred_username", jwt.getClaim("preferred_username"),
                "given_name", jwt.getClaim("given_name"),
                "family_name", jwt.getClaim("family_name"),
                "exterClientID", jwt.getClaim("exterClientID"),
                "email", jwt.getClaim("email"),
                "isTokenValid", isTokenValid
        );
    }
}
