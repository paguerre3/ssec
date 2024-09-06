package org.sec;

import lombok.AllArgsConstructor;
import org.sec.model.SysUser;
import org.sec.model.SysUserRepo;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@AllArgsConstructor
public class RegisterCtrl {
    private SysUserRepo sysUserRepo;
    //private PasswordEncoder passwordEncoder;

    @PostMapping("/register/user")
    public ResponseEntity<?> createUser(@RequestBody SysUser sysUser) {
        // no need to encode here as it will be a security break, rest protocol must receive password encoded
        // from json using the right algorithm otherwise in can be found with a main in the middle attack:
        //sysUser.setPassword(passwordEncoder.encode(sysUser.getPassword()));
        if (sysUserRepo.findByUsername(sysUser.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("User %s already exists".formatted(sysUser.getUsername()));
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(sysUserRepo.save(sysUser));
    }
}
