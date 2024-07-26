package com.br.senac.EcommerceAPI.Models;

import com.br.senac.EcommerceAPI.DTO.*;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter @Setter

@Entity
@Table(name = "credencial")
public class CredencialModel implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = false)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String senha;
    private Long idUsuario;
    @Column(nullable = false)
    private Boolean admin = true;
    private Boolean isAccountNonExpired = true;
    private Boolean isAccountNonLocked = true;
    private Boolean isCredentialsNonExpired = true;
    private Boolean isEnabled = true;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_permission", joinColumns = {@JoinColumn(name = "id_credencial")},
           inverseJoinColumns = {@JoinColumn(name = "id_user")})
    private List<Permission> permissions;

    public CredencialModel(CredencialDTO dto){
        this.email = dto.getEmail();
        this.senha = dto.getSenha();
        this.idUsuario = dto.getIdUsuario();
        this.admin = dto.isAdmin();
    }
    public CredencialModel(UsuarioInfoDTO dto) {
        this.email = dto.getEmail();
        this.senha = dto.getSenha();
    }

    public CredencialModel(AtualizarCredencialDTO dto) {
        this.email = dto.getEmail();
        this.senha = dto.getSenha();
    }

    public CredencialModel(CadastroUsuarioDTO dto) {
        this.email = dto.getEmail();
        this.senha = dto.getSenha();
    }

    public List<String> getRoles() {
        List<String> roles = new ArrayList<>();
        for (Permission permission : permissions) {
            roles.add(permission.getDescription());
        }
        return roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.permissions;
    }

    @Override
    public String getPassword() {
        return this.senha;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return Boolean.TRUE.equals(this.isAccountNonExpired);
    }

    @Override
    public boolean isAccountNonLocked() {
        return Boolean.TRUE.equals(this.isAccountNonLocked);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return Boolean.TRUE.equals(this.isCredentialsNonExpired);
    }

    @Override
    public boolean isEnabled() {
        return Boolean.TRUE.equals(this.isEnabled);
    }
}
