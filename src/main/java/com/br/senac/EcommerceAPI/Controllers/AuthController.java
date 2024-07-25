package com.br.senac.EcommerceAPI.Controllers;

import com.br.senac.EcommerceAPI.DTO.CredencialDTO;
import com.br.senac.EcommerceAPI.Services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody CredencialDTO dto) throws Exception {
        if (checkIfParamsIsNotNull(dto))
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Requisição inválida");
        var token = authService.authentication(dto);
        if(token == null)
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Requisição inválida");
        return token;
    }

    private static boolean checkIfParamsIsNotNull(CredencialDTO dto) {
        return dto == null || dto.getEmail() == null || dto.getEmail().isBlank() || dto.getSenha() == null || dto.getSenha().isBlank();
    }
}
