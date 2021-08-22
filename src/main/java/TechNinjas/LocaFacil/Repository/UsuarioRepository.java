package TechNinjas.LocaFacil.Repository;

import TechNinjas.LocaFacil.Model.UsuarioModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<UsuarioModel, Integer> {

    public Optional<UsuarioModel> findByEmail(String email);
    public Optional<UsuarioModel> findById(Integer iduser);
}
