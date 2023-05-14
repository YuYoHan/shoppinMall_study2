package com.example.study_project.entity;

import lombok.*;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@Entity
// Todo 테이블에 매핑
@Table(name = "Todo")
public class TodoEntity {
    @Id
    // ID를 자동으로 생성하겠다는 뜻
    // generator로 어떻게 ID를 생성할지 지정할 수 있다.
    // system-uuid는  @GenericGenerator에 정의된 이름이다.
    // @GenericGeneratorsms Hibernate이 제공하는 기본 Generator가 아니라
    // 나만의 Generator를 사용하고 싶을 때 사용한다.
    @GeneratedValue(generator = "system-uuid")
    @GenericGenerator(name = "system-uuid", strategy = "uuid")
    private String id;          // 이 오브젝트의 아이디
    private String userId;      // 이 오브젝트를 생성한 아이디
    private String title;       // Todo 타이틀     예) 운동하기
    private boolean done;       // true -   todo를 완료한 경우(checked)
}
