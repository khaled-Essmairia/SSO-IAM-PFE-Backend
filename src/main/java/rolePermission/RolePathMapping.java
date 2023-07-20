package rolePermission;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "role_path_mapping")
public class RolePathMapping {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @ManyToOne
    @JoinColumn(name = "path_id", nullable = false)
    private Path path;
    
    private String permission;

	public RolePathMapping(Long id, Role role, Path path, String permission) {
		super();
		this.id = id;
		this.role = role;
		this.path = path;
		this.permission = permission;
	}

	public RolePathMapping(Role role, Path path, String permission) {
		super();
		this.role = role;
		this.path = path;
		this.permission = permission;
	}

	public RolePathMapping(Role role, Path path) {
		super();
		this.role = role;
		this.path = path;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

	public Path getPath() {
		return path;
	}

	public void setPath(Path path) {
		this.path = path;
	}

	public String getPermission() {
		return permission;
	}

	public void setPermission(String permission) {
		this.permission = permission;
	}

	public RolePathMapping() {
		super();
	}




   
}


