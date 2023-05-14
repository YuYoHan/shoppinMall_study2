package com.example.study_project.controller;


import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping()
    public String test() {
        return "Hello World";
    }

    @GetMapping("/{id}")
    public String testPathVariable(@PathVariable(required = false) int id) {
        return "Hello World! Id " + id;
    }

    // ...:8080/test/testRequestParam?id=123 이런식
    @GetMapping("/testRequestParam")
    public String testRequestParam(@RequestParam(required = false) int id) {
        return "Hello World! Id " + id;
    }
}
