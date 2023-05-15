package com.example.study_project.dto;

import com.example.study_project.entity.TodoEntity;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@ToString
public class TodoDTO {
    private String id;
    private String title;
    private boolean done;

    public TodoDTO(final TodoEntity todoEntity) {
        this.id = todoEntity.getId();
        this.title = todoEntity.getTitle();
        this.done = todoEntity.isDone();
    }

    public static TodoEntity todoEntity(final TodoDTO todoDTO){
        return TodoEntity.builder()
                .id(todoDTO.getId())
                .title(todoDTO.getTitle())
                .done(todoDTO.isDone())
                .build();
    }
}
