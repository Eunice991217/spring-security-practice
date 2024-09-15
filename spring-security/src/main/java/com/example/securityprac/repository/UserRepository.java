package com.example.securityprac.repository;

import com.example.securityprac.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    // 존재하면 true, 아니면 false
    boolean existsByUsername(String username);

    // username 을 통해 UserEntity 찾기
    UserEntity findByUsername(String username);
}
