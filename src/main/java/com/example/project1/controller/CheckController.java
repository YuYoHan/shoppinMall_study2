package com.example.project1.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CheckController {
    @GetMapping("/success-oauth")
    public String check() {
        return "/success-oauth";
    }
}
