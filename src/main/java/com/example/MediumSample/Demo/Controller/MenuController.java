package com.example.MediumSample.Demo.Controller;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/menu")
public class MenuController {

    @GetMapping
    public List<Map<String, Object>> getMenuItems(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            Map<String, Object> realmAccess = (Map<String, Object>) resourceAccess.get("exterAdminConsole");
            if (realmAccess != null) {
                List<String> roles = (List<String>) realmAccess.get("roles");
                if (roles != null) {
                    if (roles.contains("admin")) {
                        return getAdminMenuItems();
                    } else if (roles.contains("user")) {
                        return getUserMenuItems();
                    }
                }
            }
        }
        return new ArrayList<>(); // Return an empty list or handle unauthorized case
    }

    private List<Map<String, Object>> getAdminMenuItems() {
        List<Map<String, Object>> menuItems = new ArrayList<>();

        Map<String, Object> homeItem = new HashMap<>();
        homeItem.put("key", "1");
        homeItem.put("label", "Home");
        homeItem.put("icon", "HomeOutlined");
        homeItem.put("path", "/");
        homeItem.put("type", "menu");

        Map<String, Object> userManagementItem = new HashMap<>();
        userManagementItem.put("key", "2");
        userManagementItem.put("label", "User Management");
        userManagementItem.put("icon", "UserOutlined");
        userManagementItem.put("type", "submenu");

        // Add sub-menu items for User Management
        List<Map<String, Object>> subMenuItems = new ArrayList<>();
        Map<String, Object> usersItem = new HashMap<>();
        usersItem.put("key", "2-1");
        usersItem.put("label", "Users");
        usersItem.put("icon", "UserOutlined");
        usersItem.put("path", "/users");
        subMenuItems.add(usersItem);

        Map<String, Object> customersItem = new HashMap<>();
        customersItem.put("key", "2-2");
        customersItem.put("label", "Customers");
        customersItem.put("icon", "UserOutlined");
        customersItem.put("path", "/customers");
        subMenuItems.add(customersItem);

        userManagementItem.put("children", subMenuItems);

        menuItems.add(homeItem);
        menuItems.add(userManagementItem);

        return menuItems;
    }


    private List<Map<String, Object>> getUserMenuItems() {
        List<Map<String, Object>> menuItems = new ArrayList<>();

        menuItems.add(createMenuItem("1", "0", 1, "Home", "HomeOutlined", "/user/home", "item", "route"));
        menuItems.add(createMenuItem("2", "0", 2, "User View", "DashboardOutlined", "/user/view", "item", "route"));
        menuItems.add(createMenuItem("3", "0", 3, "My Profile", "ProfileOutlined", "/user/profile", "item", "route"));

        return menuItems;
    }

    private Map<String, Object> createMenuItem(String id, String parentId, int order, String label, String icon, String link, String type, String action) {
        Map<String, Object> menuItem = new HashMap<>();
        menuItem.put("key", id);
        menuItem.put("parentID", parentId);
        menuItem.put("order", order);
        menuItem.put("label", label);
        menuItem.put("icon", icon);
        menuItem.put("path", link);
        menuItem.put("type", type);
        menuItem.put("onClick", action);
        return menuItem;
    }
}
