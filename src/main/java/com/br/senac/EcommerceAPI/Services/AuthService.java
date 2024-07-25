package com.br.senac.EcommerceAPI.Services;

import com.br.senac.EcommerceAPI.DTO.CredencialDTO;
import com.br.senac.EcommerceAPI.Models.CredencialModel;
import com.br.senac.EcommerceAPI.Repositories.CredencialRepository;
import com.br.senac.EcommerceAPI.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    private final CredencialRepository credencialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    public ResponseEntity<?> authentication(CredencialDTO dto) {
        CredencialModel credencial = credencialRepository.findByUsuario(dto.getEmail());
        if(passwordEncoder.matches(dto.getSenha(), credencial.getPassword())) {
            String token = tokenProvider.generateToken(credencial);
            return new ResponseEntity<>(token, HttpStatus.OK);
        }

        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
