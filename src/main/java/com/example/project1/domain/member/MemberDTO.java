package com.example.project1.domain.member;

import com.example.project1.entity.member.MemberEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.util.Optional;

@ToString
@Getter
@NoArgsConstructor
public class MemberDTO {
    private Long userId;

    @NotNull(message = "이메일은 필수 입력입니다.")
    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.")
    @Email(message = "이메일 형식에 맞지 않습니다.")
    private String userEmail;

    @NotNull(message = "이름은 필수입력입니다.")
    private String userName;
    private String nickName;

    private String userPw;
    @NotNull(message = "유저타입은 필수입력입니다.")
    private UserType userType;
    private String provider;
    private String providerId;

    @Builder
    public MemberDTO(Long userId,
                     String userEmail,
                     String userName,
                     String nickName,
                     String userPw,
                     UserType userType,
                     String provider,
                     String providerId) {
        this.userId = userId;
        this.userEmail = userEmail;
        this.userName = userName;
        this.nickName = nickName;
        this.userPw = userPw;
        this.userType = userType;
        this.provider = provider;
        this.providerId = providerId;
    }

    public static MemberDTO toMemberDTO(Optional<MemberEntity> member) {
        MemberDTO memberDTO = MemberDTO.builder()
                .userId(member.get().getUserId())
                .userEmail(member.get().getUserEmail())
                .userName(member.get().getUserName())
                .userPw(member.get().getUserPw())
                .nickName(member.get().getNickName())
                .userType(member.get().getUserType())
                .provider(member.get().getProvider())
                .providerId(member.get().getProviderId())
                .build();

        return memberDTO;
    }
}
