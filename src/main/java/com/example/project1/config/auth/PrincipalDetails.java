package com.example.project1.config.auth;

import com.example.project1.entity.member.MemberEntity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Setter
@Getter
@ToString
@NoArgsConstructor
@Slf4j
public class PrincipalDetails implements UserDetails, OAuth2User {

    // 일반 로그인 정보를 저장하기 위한 필드
    private MemberEntity member;
    // OAuth2 로그인 정보를 저장하기 위한 필드
    // attributes는 Spring Security에서 OAuth2 인증을 수행한 후에 사용자에 대한 추가 정보를 저장하는 데 사용되는 맵(Map)입니다.
    // OAuth2 인증은 사용자 인증 후에 액세스 토큰(Access Token)을 발급받게 되는데,
    // 이 토큰을 사용하여 OAuth2 서비스(provider)로부터 사용자의 프로필 정보를 요청할 수 있습니다.
    // 예를 들어, 소셜 로그인을 사용한 경우에는 attributes에는 사용자의 소셜 서비스(provider)에서 제공하는 프로필 정보가 담겨 있습니다.
    // 소셜 로그인 서비스(provider)마다 제공하는 프로필 정보가 다를 수 있습니다.
    // 일반적으로 attributes에는 사용자의 아이디(ID), 이름, 이메일 주소, 프로필 사진 URL 등의 정보가 포함됩니다.
    /*
    *   구글의 경우
    *   {
            "sub": "100882758450498962866", // 구글에서 발급하는 고유 사용자 ID
            "name": "John Doe", // 사용자 이름
            "given_name": "John", // 이름(이름 부분)
            "family_name": "Doe", // 성(성(성) 부분)
            "picture": "https://lh3.googleusercontent.com/a/AAcHTtdzQomNwZCruCcM0Eurcf8hAgBHcgwvbXEBQdw3olPkSg=s96-c", // 프로필 사진 URL
            "email": "johndoe@example.com", // 이메일 주소
            "email_verified": true, // 이메일 주소 인증 여부
            "locale": "en" // 지역 설정
        }
    * */
    private Map<String, Object> attributes;


    // 일반 로그인
    public PrincipalDetails(MemberEntity member) {
        this.member = member;
    }


    // OAuth2 로그인
    public PrincipalDetails(MemberEntity member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }

    // 해당 유저의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new SimpleGrantedAuthority("ROLE_" + member.getUserType().toString()));
        log.info("collection : " + collection);
        return collection;
    }


    // 사용자 패스워드를 반환
    @Override
    public String getPassword() {
        return member.getUserPw();
    }

    // 사용자 이름 반환
    @Override
    public String getUsername() {
        return member.getUserEmail();
    }


    // 계정 만료 여부 반환
    @Override
    public boolean isAccountNonExpired() {
        // 만료되었는지 확인하는 로직
        // true = 만료되지 않음
        return true;
    }

    // 계정 잠금 여부 반환
    @Override
    public boolean isAccountNonLocked() {
        // true = 잠금되지 않음
        return true;
    }

    // 패스워드의 만료 여부 반환
    @Override
    public boolean isCredentialsNonExpired() {
        // 패스워드가 만료되었는지 확인하는 로직
        // true = 만료되지 않음
        return true;
    }

    // 계정 사용 가능 여부 반환
    @Override
    public boolean isEnabled() {
        // 계정이 사용 가능한지 확인하는 로직
        // true = 사용 가능
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    // OAuth2 인증에서는 사용되지 않는 메서드이므로 null 반환
    public String getName() {
        return null;
    }
}
