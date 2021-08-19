package TechNinjas.LocaFacil.Services;

import TechNinjas.LocaFacil.Data.UsuarioData;
import TechNinjas.LocaFacil.Model.UsuarioModel;
import TechNinjas.LocaFacil.Repository.UsuarioRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UsuarioServiceDetails implements UserDetailsService {

    private final UsuarioRepository repository;

    public UsuarioServiceDetails(UsuarioRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String user) throws UsernameNotFoundException {
        Optional<UsuarioModel> usuario = repository.findByEmail(user);

        if(usuario.isEmpty()) {
            throw new UsernameNotFoundException("Usuario [" + user + "] não encontrado");
        }

        return new UsuarioData(usuario);
    }
}
