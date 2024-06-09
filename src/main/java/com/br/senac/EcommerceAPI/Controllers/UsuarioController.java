package com.br.senac.EcommerceAPI.Controllers;

import com.br.senac.EcommerceAPI.DTO.*;
import com.br.senac.EcommerceAPI.Models.CredencialModel;
import com.br.senac.EcommerceAPI.Models.EnderecoModel;
import com.br.senac.EcommerceAPI.Models.UsuarioModel;
import com.br.senac.EcommerceAPI.Services.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.List;

@RestController
@CrossOrigin("*")
@RequestMapping("/api/usuarios")
public class UsuarioController {

    @Autowired
    private UsuarioService usuarioService;

    @PostMapping("/criar")
    public ResponseEntity<UsuarioModel> criarCliente(@RequestBody CadastroUsuarioDTO dto) throws ParseException {
        return usuarioService.criarUsuario(dto);
    }
    @GetMapping
    public ResponseEntity<List<UsuarioModel>> listarClientes() {
        return usuarioService.listarUsuarios();
    }

    @GetMapping("/{id}")
    public ResponseEntity<UsuarioModel> buscarPorId(@PathVariable (value = "id")
                                                        Long id) throws Exception {
        return usuarioService.buscaPorId(id);
    }
    @GetMapping("/nome/{nome}")
    public ResponseEntity<UsuarioModel> buscaPorNome(@PathVariable (value = "nome")
                                                         String nome) throws Exception {
        return usuarioService.buscaPorNome(nome);
    }
    @GetMapping("/info")
    public ResponseEntity<UsuarioInfoDTO> retonaInfoUsuario(@RequestParam("id") Long id) throws Exception {
        return usuarioService.retonaDadosUsuario(id);
    }
    @PutMapping("/atualizardados")
    public ResponseEntity<UsuarioModel> atualizarUsuario(@RequestParam ("id") Long id,
                                                         @RequestBody AtualizarUsuarioDTO dto) throws Exception {
        return usuarioService.atualizarUsuario(id, dto);
    }
    @PutMapping("/atualizaremail")
    public ResponseEntity<CredencialModel> atualizarEmail(@RequestParam ("id") Long id,
                                                               @RequestBody AtualizarCredencialDTO dto) {
        return usuarioService.atualizarEmail(id, dto);

    }
    @PutMapping("/atualizarsenha")
    public ResponseEntity<CredencialModel> atualizarSenha(@RequestParam ("id") Long id,
                                                               @RequestBody AtualizarCredencialDTO dto) {
        return usuarioService.atualizarSenha(id, dto);

    }
    @PutMapping("/atualizarenderecos")
    public ResponseEntity<EnderecoModel> atualizarEndereco(@RequestParam ("id") Long id,
                                                           @RequestBody AtualizarEnderecoDTO dto) throws Exception {
        return usuarioService.atualizarEndereco(id, dto);
    }
    @DeleteMapping("/deletarendereco")
    public ResponseEntity<?> deletarEndereco(@RequestParam ("id") Long id) throws Exception {
        return usuarioService.excluirEndereco(id);
    }

    @PostMapping("/novoendereco")
    public ResponseEntity<EnderecoModel> novoEndereco(@RequestParam ("id") Long id,
                                                      @RequestBody EnderecoDTO dto) throws Exception {
        return usuarioService.novoEndereco(id, dto);
    }

}
