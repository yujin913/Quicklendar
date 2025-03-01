package com.capstone.quicklendar.repository.user;

import com.capstone.quicklendar.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email); // 이메일로 사용자 찾기
    Optional<User> findByEmailAndProvider(String email, String provider); // 이메일과 OAuth 제공자(provider)로 사용자 찾기
}
