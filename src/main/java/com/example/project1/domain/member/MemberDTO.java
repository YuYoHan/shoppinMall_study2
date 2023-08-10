package com.example.project1.domain.member;

import com.example.project1.domain.member.embedded.AddressDTO;
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
    private String provider;        // 예) google
    private String providerId;

    private AddressDTO addressDTO;


    @Builder
    public MemberDTO(Long userId,
                     String userEmail,
                     String userName,
                     String nickName,
                     String userPw,
                     UserType userType,
                     String provider,
                     String providerId,
                     AddressDTO addressDTO) {
        this.userId = userId;
        this.userEmail = userEmail;
        this.userName = userName;
        this.nickName = nickName;
        this.userPw = userPw;
        this.userType = userType;
        this.provider = provider;
        this.providerId = providerId;
        this.addressDTO = addressDTO;
    }

    public static MemberDTO toMemberDTO(MemberEntity member) {

            MemberDTO memberDTO = MemberDTO.builder()
                    .userId(member.getUserId())
                    .userEmail(member.getUserEmail())
                    .userName(member.getUserName())
                    .userPw(member.getUserPw())
                    .nickName(member.getNickName())
                    .userType(member.getUserType())
                    .provider(member.getProvider())
                    .providerId(member.getProviderId())
                    .addressDTO(AddressDTO.builder()
                            .userAddr(member.getAddress().getUserAddr())
                            .userAddrDetail(member.getAddress().getUserAddrDetail())
                            .userAddrEtc(member.getAddress().getUserAddrEtc())
                            .build())
                    .build();

            return memberDTO;
        }


    }
