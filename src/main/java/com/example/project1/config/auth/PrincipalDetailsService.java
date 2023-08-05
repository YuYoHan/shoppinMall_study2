package com.example.project1.config.auth;

import com.example.project1.entity.member.MemberEntity;
import com.example.project1.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login ← 이 때 동작을 함
// 일반 로그인 시 회원 가입한 정보를 가지고 조회해서 찾아와서
// PrincipalDetails 에 넘겨준다.

// 소셜 로그인의 경우 JWT 를 안하면 여기서 작업을 해서 정보를 가지고 오지만
// JWT 를 사용할거면 여기서 작업하지 않는다.

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    // 시큐리티 session = Authentication = UserDetails
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        MemberEntity member = memberRepository.findByUserEmail(userEmail);
        log.info("user in PrincipalDetailsService : " + member);
        return new PrincipalDetails(member);
    }
}
