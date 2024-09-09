package org.sec;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.sec.jwt.JwtSvc;
import org.sec.model.SysUserDetailsSvc;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.util.StringUtils;

import java.io.IOException;

@Configuration
@AllArgsConstructor
public class AuthFilter extends OncePerRequestFilter {
    private JwtSvc jwtSvc;
    private SysUserDetailsSvc userSvc;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String bearerPrefix = "Bearer ";
        if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith(bearerPrefix)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract JWT from header:
        String jwt = authHeader.substring(bearerPrefix.length());
        String username = this.jwtSvc.extractUsername(jwt);
        if (!StringUtils.isEmpty(username)
                // ensure user isn't already authenticated:
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userSvc.loadUserByUsername(username);
            if (userDetails != null && !this.jwtSvc.isTokenExpired(jwt)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username,
                        userDetails.getPassword(),
                        userDetails.getAuthorities()
                );
                // set the details of the client who is making teh request for tracking purposes,
                // e.g. for running an investigation under production environment:
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Do authentication success:
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
