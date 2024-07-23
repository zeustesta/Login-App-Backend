package com.zeustesta.apirest.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;


@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class demoController {
  
  @PostMapping(value = "demo")
  public String welcome() {
      return "¡Bienvenido a la demo!";
  }
  
}
