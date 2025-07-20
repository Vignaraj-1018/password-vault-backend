package com.passwordVault.backend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class mainController {

    @GetMapping("/hello")
    public ResponseEntity<?> helloWorld(){
        return new ResponseEntity<>("Hello, World!",HttpStatus.OK);
    }

    @GetMapping("/example")
    public ResponseEntity<?> example(){
        return new ResponseEntity<>("Hello, World!",HttpStatus.OK);
    }
}
