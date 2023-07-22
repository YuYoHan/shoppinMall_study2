package com.example.project1.entity.member.embedded;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Embeddable;

// 임베디드 타입을 사용하려면 넣어야 한다.
@Embeddable
@ToString
@Getter
@NoArgsConstructor
public class AddressEntity {
    private String userAddr;
    private String userAddrDetail;
    private String userAddrEtc;

    @Builder
    public AddressEntity(String userAddr, String userAddrDetail, String userAddrEtc) {
        this.userAddr = userAddr;
        this.userAddrDetail = userAddrDetail;
        this.userAddrEtc = userAddrEtc;
    }
}
