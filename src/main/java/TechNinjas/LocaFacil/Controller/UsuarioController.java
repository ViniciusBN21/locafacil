package TechNinjas.LocaFacil.Controller;

import TechNinjas.LocaFacil.Model.UsuarioModel;
import TechNinjas.LocaFacil.Repository.UsuarioRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@Api("API SISTEMA LOGIN")
@CrossOrigin(origins = "*")
public class UsuarioController {

    private final UsuarioRepository repository;
    private final PasswordEncoder encoder;

    public UsuarioController(UsuarioRepository repository, PasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    @GetMapping("/listarTodos")
    @ApiOperation(value = "Retorna lista de usuarios")
    public ResponseEntity<List<UsuarioModel>> listarTodos() {
        return ResponseEntity.ok(repository.findAll());
    }

    @PostMapping("/createuser")
    @ApiOperation(value = "Cria novo usuario")
    public ResponseEntity<UsuarioModel> criarUsuario(@RequestBody UsuarioModel usuario) {
        usuario.setNome(usuario.getNome());
        usuario.setEmail(usuario.getEmail());
        usuario.setSenha(encoder.encode(usuario.getSenha()));
        usuario.setTypeuser(1);
        return ResponseEntity.ok(repository.save(usuario));
    }

    @GetMapping("/validarSenha")
    @ApiOperation(value = "Faz a validação da senha")
    public ResponseEntity<Boolean> validarSenha(@RequestParam String email, @RequestParam String senha) {
        Optional<UsuarioModel> optUsuario = repository.findByEmail(email);
        if (optUsuario.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }

        UsuarioModel usuario = optUsuario.get();
        boolean valid = encoder.matches(senha, usuario.getSenha());

        HttpStatus status = (valid) ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;
        return ResponseEntity.status(status).body(valid);
    }

    @GetMapping("/defpassword")
    @ApiOperation(value = "Retorna a senha direcionada a esse email")
    public String recuperarSenha(@RequestParam String email){
        Optional<UsuarioModel> optUsuario = repository.findByEmail(email);
        if (optUsuario.isEmpty()){
            return "Email invalido ou em branco";
        }
        UsuarioModel usuario = optUsuario.get();
        return  "Senha solicitada: " + usuario.getSenha();
    }

    @PutMapping("/alterarUsuario")
    @ApiOperation(value = "Atualiza usuario")
    public ResponseEntity<UsuarioModel> alterarUsuario(@RequestBody UsuarioModel usuario) {
        return ResponseEntity.ok(repository.save(usuario));
    }

    @DeleteMapping("/deletarUsuario")
    @ApiOperation(value = "Deleta usuario")
    public void deleteUsuario(@RequestBody UsuarioModel usuario){
        repository.delete(usuario);
    }
}
