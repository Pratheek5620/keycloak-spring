package com.example.MediumSample.Demo.Controller;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/menu")
public class MenuController {

    @GetMapping
    public Map<String, List<String>> getMenuItems(JwtAuthenticationToken authentication) {
        Jwt jwt = (Jwt) authentication.getCredentials();
        String exterClientID = jwt.getClaim("exterClientID");
        System.out.println("exterClientID from JWT: " + exterClientID);

        // Based on the exterClientID and role, decide which menu items to return
        List<String> menuItems;
        if (exterClientID.equals("admin")) {
            menuItems = List.of("Admin Dashboard", "User list", "Stats");
        } else {
            menuItems = List.of("Dashboard", "User profile", "Batteries");
        }

        return Map.of("menuItems", menuItems);
    }
}
