package org.sec;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.sec.model.SysUserDetailsSvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityCnf {
    private SysUserDetailsSvc sysUserDetailsSvc;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // Cross-Site Request Forgery (CSRF) is a type of web security vulnerability that tricks a user’s browser
                // into performing actions they didn’t intend to perform on a different site.
                // This happens because the browser automatically includes credentials like cookies with each request,
                // allowing an attacker to exploit the trust a web application has in the user’s browser.
                // To avoid this CSRF protection is "enabled" by default in Spring Security, i.e.
                // disallowing calls from all suspicions address that don't belong to the company.
                // In this case we allow "localhost" because /registration will be performed from a ReST client app
                // that runs locally:
                .csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository())
                        .requireCsrfProtectionMatcher(new RequestMatcher() {
                            @Override
                            public boolean matches(HttpServletRequest request) {
                                // Disable CSRF only for localhost:
                                return isValidHost(request.getRemoteHost());
                            }
                        }))
                .authorizeHttpRequests(registry -> {
                    // avoid using regex like ^/welcome$ as requestMatchers by default does not use regex matching
                    // unless explicitly configured to do so.
                    // Instead, it performs ant-style matching (which uses * and ** wildcards, not regex).
                    registry.requestMatchers("/home", "/welcome", "/register/user").permitAll();
                    registry.requestMatchers("/admin/**").hasRole("admin");
                    registry.requestMatchers("/user/**").hasRole("user");
                    // this disables default Web Sec form login, i.e. wall including user and pass:
                    registry.anyRequest().authenticated();
                })
                // to enable back form login of Spring Web Sec:
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .build();
    }

    /**
     * Once enabled it will stop showing auto-generated dev password by default in Spring console.
     * This service allows handling users.
     *
     * @return UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService() {
        //return loadUsersInMemory();
        return this.loadUsersFromDb();
    }

    private UserDetailsService loadUsersInMemory() {
        UserDetails normalUser = User.builder()
                .username("cami")
                // encoded password that can't be engineering reversed:
                .password("$2a$12$VoQJGEDrm4gdDy9tB/SsiuTrI98O.Z6NeIyhttiah7F6M3xq9ER7q")
                .roles("user")
                .build();
        UserDetails adminUser = User.builder()
                .username("male")
                // encoded password that can't be engineering reversed:
                .password("$2a$12$6pd9xnB3IK//QRfg/tJOteHRjgb74JLvkiIVRhRU.JdCeWf8uuEX2")
                .roles("admin", "user")
                .build();
        return new InMemoryUserDetailsManager(normalUser, adminUser);
    }

    private UserDetailsService loadUsersFromDb() {
        // reference to the service that loads all users available from DB into Spring Security:
        return sysUserDetailsSvc;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        // Database Access Object Provider required for Setting Encoder at "Database Level":
        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setPasswordEncoder(passwordEncoder());
        daoProvider.setUserDetailsService(sysUserDetailsSvc);
        return daoProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private static boolean isValidHost(final String host) {
        return Optional.ofNullable(host)
                .map(localHost -> "127.0.0.1".equals(host)
                        || "0:0:0:0:0:0:0:1".equals(host)
                        || "localhost".equals(host))
                .orElse(false);
    }
 }
