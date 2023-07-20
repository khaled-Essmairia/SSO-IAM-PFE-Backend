package rolePermission;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebMvcSecurity
@RestController

public class Config {

	@Autowired
	RolePathMappingRepository rolePathMappingRepository;
	@Autowired
	RoleRepository RoleRepository;
	@Autowired
	PathRepository PathRepository;
	protected void configure(HttpSecurity http) throws Exception {
	    // Retrieve all role-path configurations from repository
	    List<RolePathMapping> rolePaths = rolePathMappingRepository.findAll();

	    // Configure HttpSecurity for each role-path configuration
	    for (RolePathMapping rolePath : rolePaths) {
	        String roleName = rolePath.getRole().getName();
	        String path = rolePath.getPath().getPath();
	        String permission = rolePath.getPermission();

	        http.authorizeRequests()
	            .antMatchers(path).access("hasRole('" + roleName + "')")
	            .and()
	            .authorizeRequests()
	            .antMatchers(permission).hasRole(roleName)
	           // .anyRequest().hasPermission(permission)
	            .and()
	            .csrf();
	    }
	}

	
	@PostMapping("/configure-security")
	public String configureSecurity(@RequestParam String role, @RequestParam String path, @RequestParam String permission) throws Exception {
	    // Save role-path configuration to repository
		RolePathMapping rolePath = new RolePathMapping();
	    rolePath.setRole(RoleRepository.findByName(role));
	    rolePath.setPath(PathRepository.findByPath(path));
	    rolePath.setPermission(permission);
	    rolePathMappingRepository.save(rolePath);

	    // Return success message
	    return "security-configured";
	}
}
