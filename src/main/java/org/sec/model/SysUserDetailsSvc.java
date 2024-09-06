package org.sec.model;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class SysUserDetailsSvc implements UserDetailsService {
    private SysUserRepo repo;
    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return this.repo.findByUsername(username)
                .map(u -> {
                    return User.builder()
                            .username(u.getUsername())
                            .password(u.getPassword())
                            .roles(SysUserDetailsSvc.getRolesOrDefault(u.getRoles()))
                            .build();
                }).orElseThrow(() -> new UsernameNotFoundException("User %s not found".formatted(username)));
    }

    private static String[] getRolesOrDefault(final String roles) {
        // roles are stored separated by comma if there is more than one:
        return roles != null && !roles.isEmpty() ? roles.split(",") : new String[]{"user"};
    }
}
