package org.sec;

import jdk.jfr.Frequency;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConf {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.
                authorizeHttpRequests(registry -> {
                    // avoid using regex like ^/welcome$ as requestMatchers by default does not use regex matching
                    // unless explicitly configured to do so.
                    // Instead, it performs ant-style matching (which uses * and ** wildcards, not regex).
                    registry.requestMatchers("/home", "/welcome").permitAll();
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
        // load users in memory:
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
 }
