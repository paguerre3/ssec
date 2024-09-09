package org.sec;

import lombok.AllArgsConstructor;
import org.sec.jwt.JwtSvc;
import org.sec.jwt.LoginForm;
import org.sec.model.SysUserDetailsSvc;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class AuthCtrl {
    private AuthenticationManager authMgr;
    private JwtSvc jwtSvc;
    private SysUserDetailsSvc userSvc;

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody LoginForm form) {
        var authentication = authMgr.authenticate(new UsernamePasswordAuthenticationToken(form.username(), form.password()));
        if (authentication.isAuthenticated()) {
           return jwtSvc.generateToken(userSvc.loadUserByUsername(form.username()));
        }
        throw new UsernameNotFoundException("Invalid credentials");
    }
}
