package org.sec;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthSuccessMgr implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // Check the role of the authenticated user
        if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_admin"))) {
            // Redirect to admin page if user has admin role
            response.sendRedirect("/admin/home");
        } else if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_user"))) {
            // Redirect to user home if user has user role
            response.sendRedirect("/user/home");
        } else {
            // Default redirection if no known role is found
            response.sendRedirect("/home");
        }
    }
}