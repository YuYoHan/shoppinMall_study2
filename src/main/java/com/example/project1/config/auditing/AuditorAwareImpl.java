package com.example.project1.config.auditing;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        // 인증받은 유저가 SecurityContextHolder에 등록이 되는데
        // 그곳에서 가져오는 것이다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String userEmail = "";
        if(authentication != null) {
            // 현재 로그인한 사용자의 정보를 조회하여 사용자의 이름을 등록자와 수정자로 지정
            userEmail = authentication.getName();
        }
        return Optional.of(userEmail);
    }
}
