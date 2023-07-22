package com.example.project1.domain.member.embedded;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Getter
@NoArgsConstructor
public class AddressDTO {
    private String userAddr;
    private String userAddrDetail;
    private String userAddrEtc;

    @Builder
    public AddressDTO(String userAddr, String userAddrDetail, String userAddrEtc) {
        this.userAddr = userAddr;
        this.userAddrDetail = userAddrDetail;
        this.userAddrEtc = userAddrEtc;
    }
}
