package org.sec;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.sec.model.SysUserDetailsSvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Optional;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityCnf {
    private SysUserDetailsSvc sysUserDetailsSvc;
    private AuthSuccessMgr authSuccessMgr;
    private AuthFilter authfilter;

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
                .csrf(cnf -> cnf.csrfTokenRepository(new HttpSessionCsrfTokenRepository())
                        .requireCsrfProtectionMatcher(new RequestMatcher() {
                            @Override
                            public boolean matches(HttpServletRequest request) {
                                // Disable CSRF only for localhost:
                                var rh = request.getRemoteHost();
                                return !isValidHost(rh);
                            }
                        }))
                .authorizeHttpRequests(registry -> {
                    // avoid using regex like ^/welcome$ as requestMatchers by default does not use regex matching
                    // unless explicitly configured to do so.
                    // Instead, it performs ant-style matching (which uses * and ** wildcards, not regex).
                    registry.requestMatchers("/home", "/welcome", "/register/user", "/authenticate").permitAll();
                    registry.requestMatchers("/admin/**").hasRole("admin");
                    registry.requestMatchers("/user/**").hasRole("user");
                    // this disables default Web Sec form login, i.e. wall including user and pass:
                    registry.anyRequest().authenticated();
                })
                // to enable Login form of Spring Web Sec -including Logout:
                //.formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                // (Note that customizing a Login page disables Logout already provided by Spring Web Sec).
                .formLogin(cnf -> cnf.loginPage("/login").successHandler(authSuccessMgr).permitAll())
                // add JWT authentication filter before UsernamePasswordAuthenticationFilter provided by Spring Web Sec:
                .addFilterBefore(authfilter, UsernamePasswordAuthenticationFilter.class)
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
    public AuthenticationManager authenticationManager() {
        // new Auth Manager required for JWT Authentication:
        return new ProviderManager(authenticationProvider());
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
