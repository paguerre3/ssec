package org.sec.model;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SysUserRepo extends JpaRepository<SysUser, Long> {
    Optional<SysUser> findByUsername(String username);
}
