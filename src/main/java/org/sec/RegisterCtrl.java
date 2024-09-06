package org.sec;

import lombok.AllArgsConstructor;
import org.sec.model.SysUser;
import org.sec.model.SysUserRepo;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class RegisterCtrl {
    private SysUserRepo sysUserRepo;
    //private PasswordEncoder passwordEncoder;

    @PostMapping("/register/user")
    public SysUser createUser(@RequestBody SysUser sysUser) {
        // no need to encode here as it will be a security break, rest protocol must receive password encoded
        // from json using the right algorithm otherwise in can be found with a main in the middle attack:
        //sysUser.setPassword(passwordEncoder.encode(sysUser.getPassword()));
        return sysUserRepo.save(sysUser);
    }
}
