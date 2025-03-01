package com.capstone.quicklendar.service.user;

import com.capstone.quicklendar.domain.user.User;
import com.capstone.quicklendar.domain.user.UserType;
import com.capstone.quicklendar.repository.user.UserRepository;
import com.capstone.quicklendar.util.dto.UpdateProfileRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import com.capstone.quicklendar.repository.user.OAuthUserRepository;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OAuthUserRepository oauthUserRepository;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       OAuthUserRepository oauthUserRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.oauthUserRepository = oauthUserRepository;
    }

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;

    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String naverClientSecret;


    public Long join(User user) {
        validateDuplicateUser(user);
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        user.setUserType(UserType.LOCAL);
        user.setEnabled(true); // 기본값 활성화
        userRepository.save(user);
        return user.getId();
    }


    private void validateDuplicateUser(User user) {
        userRepository.findByEmail(user.getEmail()).ifPresent(m -> {
            throw new IllegalStateException("이미 존재하는 이메일입니다.");
        });
    }


    // 비밀번호 유효성 검사
    private void validatePassword(String password) {
        if (password.length() < 8) {
            throw new IllegalArgumentException("비밀번호는 최소 8자 이상이어야 합니다.");
        }

        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("비밀번호에는 최소 하나의 대문자가 포함되어야 합니다.");
        }

        if (!password.matches(".*[a-z].*")) {
            throw new IllegalArgumentException("비밀번호에는 최소 하나의 소문자가 포함되어야 합니다.");
        }

        if (!password.matches(".*\\d.*")) {
            throw new IllegalArgumentException("비밀번호에는 최소 하나의 숫자가 포함되어야 합니다.");
        }

        if (!password.matches(".*[!@#\\$%\\^&\\*].*")) {
            throw new IllegalArgumentException("비밀번호에는 최소 하나의 특수문자가 포함되어야 합니다.");
        }
    }


    // 회원 탈퇴 로직
    @Transactional
    public void deleteAccount(Long userId) {
        Optional<User> user = userRepository.findById(userId);

        if (user.isPresent()) {
            userRepository.deleteById(userId);  // 회원 정보 삭제
        } else {
            throw new IllegalArgumentException("해당 회원이 존재하지 않습니다.");
        }
    }


    @Transactional
    public void updateProfile(UpdateProfileRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());
        if (optionalUser.isEmpty()) {
            throw new IllegalArgumentException("사용자를 찾을 수 없습니다.");
        }
        User user = optionalUser.get();
        user.setName(request.getName());
        user.setPhone(request.getPhone());
        if (request.getPassword() != null && !request.getPassword().trim().isEmpty()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }
    }


    @Transactional
    public void deleteGoogleAccount(String email) {
        // 이메일로 사용자 조회
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 해당 계정이 구글 연동 계정인지 확인
        if (user.getProvider() == null || !user.getProvider().equals("google")) {
            throw new IllegalArgumentException("구글 연동된 계정이 아닙니다.");
        }

        // 구글 OAuth 토큰이 존재하면, 구글의 토큰 철회 API를 호출하여 액세스 토큰 철회 시도
        if (user.getOauthToken() != null && user.getOauthToken().getAccessToken() != null) {
            String accessToken = user.getOauthToken().getAccessToken();
            String revokeUrl = "https://oauth2.googleapis.com/revoke?token=" + accessToken;
            RestTemplate restTemplate = new RestTemplate();
            try {
                ResponseEntity<String> revokeResponse = restTemplate.postForEntity(revokeUrl, null, String.class);
                // 철회가 성공해도, 구글에서 200 응답을 주지 않는 경우도 있으므로 로그만 남깁니다.
                System.out.println("Google token revocation response: " + revokeResponse.getStatusCode());
            } catch (Exception e) {
                // 토큰 철회 실패 시에도 회원 탈퇴를 진행할 수 있도록 로그만 남깁니다.
                System.err.println("Google token revocation failed: " + e.getMessage());
            }
            // 데이터베이스 상에서는 OAuth 토큰 삭제
            oauthUserRepository.delete(user.getOauthToken());
        }

        // 사용자 자체 삭제 (회원 탈퇴)
        userRepository.delete(user);
    }


    @Transactional
    public void deleteNaverAccount(String email) {
        // 이메일로 사용자 조회
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 해당 계정이 네이버 연동 계정인지 확인
        if (user.getProvider() == null || !user.getProvider().equals("naver")) {
            throw new IllegalArgumentException("네이버 연동된 계정이 아닙니다.");
        }

        // 네이버 OAuth 토큰이 존재하면 네이버의 토큰 철회 API 호출
        if (user.getOauthToken() != null && user.getOauthToken().getAccessToken() != null) {
            String accessToken = user.getOauthToken().getAccessToken();
            String revokeUrl = "https://nid.naver.com/oauth2.0/token?grant_type=delete"
                    + "&client_id=" + naverClientId
                    + "&client_secret=" + naverClientSecret
                    + "&access_token=" + accessToken
                    + "&service_provider=NAVER";
            RestTemplate restTemplate = new RestTemplate();
            try {
                ResponseEntity<String> revokeResponse = restTemplate.postForEntity(revokeUrl, null, String.class);
                System.out.println("Naver token revocation response: " + revokeResponse.getStatusCode());
            } catch (Exception e) {
                System.err.println("Naver token revocation failed: " + e.getMessage());
            }
            // 데이터베이스에서 OAuth 토큰 삭제
            oauthUserRepository.delete(user.getOauthToken());
        }
        // 사용자 계정 삭제 (회원 탈퇴 처리)
        userRepository.delete(user);
    }
}
