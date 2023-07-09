package com.example.project1.config.oauth2.provider;

import java.util.Map;

public class NaverUserInfo  implements OAuth2UserInfo{
    // oauth2User.getAttributes()를 받음
    private Map<String,Object> attributes;

    // PrincipalOauth2UserService에서 new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"))로
    // Oauth2 네이버 로그인 정보를 받아온다.
    // → {id=5SN-ML41CuX_iAUFH6-KWbuei8kRV9aTHdXOOXgL2K0, email=zxzz8014@naver.com, name=전혜영}
    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String)attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getEmail() {
        return (String)attributes.get("email");
    }

    @Override
    public String getName() {
        return (String)attributes.get("name");
    }
}
