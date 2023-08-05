package com.example.project1.config.oauth2;

import com.example.project1.config.auth.PrincipalDetails;
import com.example.project1.config.jwt.JwtProvider;
import com.example.project1.config.oauth2.provider.GoogleUserInfo;
import com.example.project1.config.oauth2.provider.NaverUserInfo;
import com.example.project1.config.oauth2.provider.OAuth2UserInfo;
import com.example.project1.domain.jwt.TokenDTO;
import com.example.project1.domain.member.MemberDTO;
import com.example.project1.domain.member.UserType;
import com.example.project1.entity.jwt.TokenEntity;
import com.example.project1.entity.member.MemberEntity;
import com.example.project1.repository.jwt.TokenRepository;
import com.example.project1.repository.member.MemberRepository;
import com.example.project1.service.member.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

// 소셜 로그인하면 사용자 정보를 가지고 온다.
// 가져온 정보와 함께 PrincipalDetails 객체를 생성합니다.
@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final MemberRepository memberRepository;
    private final JwtProvider jwtProvider;
    private final TokenRepository tokenRepository;


    // 구글로부터 받은 userReuest 데이터에 대한 후처리되는 함수
    @Override
    public PrincipalDetails loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // registrationId로 어떤 OAuth로 로그인 했는지 확인가능
        log.info("clientRegistration in PrincipalOauth2UserService : " + userRequest.getClientRegistration() );
        log.info("accessToken in PrincipalOauth2UserService : " + userRequest.getAccessToken().getTokenValue() );

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글 로그인 버튼 클릭 →구글 로그인 창 → 로그인 완료 → code 를 리턴(OAuth-Client 라이브러리) → AccessToken 요청
        // userRequest 정보 → 회원 프로필 받아야함(loadUser 함수 호출) → 구글로부터 회원 프로필을 받아준다.
        log.info("getAttributes in PrincipalOauth2UserService : " + oAuth2User.getAttributes());

        // 회원가입을 강제로 진행
        OAuth2UserInfo oAuth2UserInfo = null;

        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청");
            // 네이버는 response를 json으로 리턴을 해주는데 아래의 코드가 받아오는 코드다.
            // response={id=5SN-ML41CuX_iAUFH6-KWbuei8kRV9aTHdXOOXgL2K0, email=zxzz8014@naver.com, name=전혜영}
            // 위의 정보를 NaverUserInfo에 넘기면
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else {
            log.info("구글과 네이버만 지원합니다.");
        }

        // 사용자가 로그인한 소셜 서비스(provider)를 가져옵니다.
        // 예를 들어, "google" 또는 "naver"와 같은 값을 가질 수 있습니다.
        String provider = oAuth2UserInfo.getProvider();
        // 사용자의 소셜 서비스(provider)에서 발급된 고유한 식별자를 가져옵니다.
        // 이 값은 해당 소셜 서비스에서 유니크한 사용자를 식별하는 용도로 사용됩니다.
        String providerId = oAuth2UserInfo.getProviderId();
        // 예) google_109742856182916427686
        String userName = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("get");
        // 사용자의 이메일 주소를 가져옵니다. 소셜 서비스에서 제공하는 이메일 정보를 사용합니다.
        String email = oAuth2UserInfo.getEmail();
        // 사용자의 권한 정보를 설정합니다. UserType.
        // 여기서는 소셜로그인으로 가입하면 무조건 User로 권한을 주는 방식으로 했습니다.
        UserType role = UserType.USER;

        // UUID를 사용하여 랜덤한 문자열 생성
        UUID uuid = UUID.randomUUID();
        // External User 줄임말 : EU
        String randomNickName =
                "EU" + uuid.toString().replace("-", "").substring(0, 9);


        // 이메일 주소를 사용하여 이미 해당 이메일로 가입된 사용자가 있는지 데이터베이스에서 조회합니다.
        MemberEntity member = memberRepository.findByUserEmail(email);

        if(member == null) {
            log.info("OAuth 로그인이 최초입니다.");
            log.info("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓");
            log.info("OAuth 자동 회원가입을 진행합니다.");


            member = MemberEntity.builder()
                    .userName(userName)
                    .userPw(password)
                    .userEmail(email)
                    .userType(role)
                    .provider(provider)
                    .providerId(providerId)
                    .nickName(randomNickName)
                    .build();

            log.info("userEmail in PrincipalOauth2UserService : " + member.getUserEmail());
            log.info("userName in PrincipalOauth2UserService : " + member.getUserName());
            log.info("userPw in PrincipalOauth2UserService : " + member.getUserPw());
            log.info("userType in PrincipalOauth2UserService : " + member.getUserType());
            log.info("provider in PrincipalOauth2UserService : " + member.getProvider());
            log.info("providerId in PrincipalOauth2UserService : " + member.getProviderId());
            log.info("nickName in PrincipalOauth2UserService : " + member.getNickName());


            MemberEntity save = memberRepository.save(member);

            // 소셜 로그인을 통해 사용자 정보를 받아온 후,
            // 해당 정보로 UsernamePasswordAuthenticationToken 을 생성
            // 이는 Spring Security의 일반적인 Authentication 객체 중 하나입니다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(email, password);
            // 사용자의 역할(role)에 해당하는 권한 정보를 가져오는 메서드를 호출하여 권한 리스트를 생성합니다.
            List<GrantedAuthority> authoritiesForUser = getAuthoritiesForUser(save);
            // jwtProvider 객체를 사용하여 사용자 정보와 권한을 기반으로 JWT 토큰을 생성
            TokenDTO token = jwtProvider.createTokenForOAuth2(authentication, authoritiesForUser);

            String accessToken = token.getAccessToken();

            // 생성된 JWT 토큰을 문자열로 변환하여 저장
            String result = resolveToken(accessToken);
            log.info("result in in PrincipalOauth2UserService : " + result);

            // JWT 토큰을 검증하고 유효한 토큰인지 확인
            if(StringUtils.hasText(result) && jwtProvider.validateToken(result)) {
                // 유효한 JWT 토큰을 기반으로 Authentication 객체를 생성합니다.
                // 이는 사용자의 인증 정보를 나타냅니다.
                Authentication authenticationResult = jwtProvider.getAuthentication(result);
                log.info("authenticationResult in PrincipalOauth2UserService : " + authenticationResult);
                // Spring Security의 SecurityContextHolder를 사용하여 현재 인증 정보를 설정합니다.
                // 이를 통해 현재 사용자가 인증된 상태로 처리됩니다.
                SecurityContextHolder.getContext().setAuthentication(authenticationResult);
            }

            // 생성된 JWT 토큰을 엔티티로 변환하여 저장하기 위해 TokenEntity 객체로 변환합니다.
            TokenEntity tokenEntity = TokenEntity.toTokenEntity(token);
            tokenRepository.save(tokenEntity);



        } else {
            log.info("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
            MemberEntity findUser = memberRepository.findByUserEmail(email);
            log.info("findUser in PrincipalOauth2UserService : " + findUser);
            TokenEntity find = tokenRepository.findByUserEmail(findUser.getUserEmail());

            if(find != null) {
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(findUser.getUserEmail(), findUser.getUserPw());

                List<GrantedAuthority> authorities = getAuthoritiesForUser(findUser);
                TokenDTO tokenForOAuth2 =
                        jwtProvider.createTokenForOAuth2(authentication, authorities);

                String accessToken = tokenForOAuth2.getAccessToken();

                String result = resolveToken(accessToken);
                log.info("result in in PrincipalOauth2UserService : " + result);

                // JWT 토큰을 검증하고 유효한 토큰인지 확인
                if(StringUtils.hasText(result) && jwtProvider.validateToken(result)) {
                    // 유효한 JWT 토큰을 기반으로 Authentication 객체를 생성합니다.
                    // 이는 사용자의 인증 정보를 나타냅니다.
                    Authentication authenticationResult = jwtProvider.getAuthentication(result);
                    log.info("authenticationResult in PrincipalOauth2UserService : " + authenticationResult);
                    // Spring Security의 SecurityContextHolder를 사용하여 현재 인증 정보를 설정합니다.
                    // 이를 통해 현재 사용자가 인증된 상태로 처리됩니다.
                    SecurityContextHolder.getContext().setAuthentication(authenticationResult);
                }
                // 생성된 JWT 토큰을 엔티티로 변환하여 저장하기 위해 TokenEntity 객체로 변환합니다.
                TokenEntity tokenEntity = TokenEntity.toTokenEntity(tokenForOAuth2);
                tokenRepository.save(tokenEntity);
            }
        }

        OAuth2User oAuth2User1 = super.loadUser(userRequest);
        log.info("getAttributes in PrincipalOauth2UserService : " + oAuth2User1.getAttributes());
        // attributes가 있는 생성자를 사용하여 PrincipalDetails 객체 생성
        // 소셜 로그인인 경우에는 attributes도 함께 가지고 있는 PrincipalDetails 객체를 생성하게 됩니다.
        PrincipalDetails principalDetails = new PrincipalDetails(member, oAuth2User.getAttributes());
        log.info("principalDetails in PrincipalOauth2UserService : " + principalDetails);
        return principalDetails;
    }

    private List<GrantedAuthority> getAuthoritiesForUser(MemberEntity member) {
        // 예시: 데이터베이스에서 사용자의 권한 정보를 조회하는 로직을 구현
        // member 객체를 이용하여 데이터베이스에서 사용자의 권한 정보를 조회하는 예시로 대체합니다.
        UserType role = member.getUserType();  // 사용자의 권한 정보를 가져오는 로직 (예시)

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));
        log.info("role in PrincipalOauth2UserService : " + role.name());
        log.info("authorities in PrincipalOauth2UserService : " + authorities);
        return authorities;
    }

    // 토큰을 Bearer 이거를 제거하기 위해 만듬
    private String resolveToken(String token) {
        if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        } else if(StringUtils.hasText(token)){
            return token;
        }else {
            return null;
        }
    }

}
