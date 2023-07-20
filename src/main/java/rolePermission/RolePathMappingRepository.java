package rolePermission;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolePathMappingRepository extends JpaRepository<RolePathMapping, Long> {

    List<RolePathMapping> findByRole(Role role);
}