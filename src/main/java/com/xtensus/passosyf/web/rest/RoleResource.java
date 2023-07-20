package com.xtensus.passosyf.web.rest;

import com.xtensus.passosyf.domain.Role;
import com.xtensus.passosyf.repository.RoleRepository;
import com.xtensus.passosyf.service.RoleService;
import com.xtensus.passosyf.web.Authorize;
import com.xtensus.passosyf.web.rest.UserController;
import com.xtensus.passosyf.web.rest.errors.BadRequestAlertException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import tech.jhipster.web.util.HeaderUtil;
import tech.jhipster.web.util.PaginationUtil;
import tech.jhipster.web.util.ResponseUtil;

/**
 * REST controller for managing {@link com.xtensus.passosyf.domain.Role}.
 */
@RestController
@RequestMapping("/api")
public class RoleResource {

    private final Logger log = LoggerFactory.getLogger(RoleResource.class);

    @Autowired
    private Keycloak keycloak;

    private static final String ENTITY_NAME = "role";

    @Value("${jhipster.clientApp.name}")
    private String applicationName;

    private final RoleService roleService;

    private final RoleRepository roleRepository;

    public RoleResource(RoleService roleService, RoleRepository roleRepository) {
        this.roleService = roleService;
        this.roleRepository = roleRepository;
    }

    /**
     * {@code POST  /roles} : Create a new role.
     *
     * @param role the role to create.
     * @return the {@link ResponseEntity} with status {@code 201 (Created)} and with body the new role, or with status {@code 400 (Bad Request)} if the role has already an ID.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    // @PostMapping("/roles")
    public ResponseEntity<Role> createRole(@Valid @RequestBody Role role) throws URISyntaxException {
        log.debug("REST request to save Role : {}", role);
        if (role.getId() != null) {
            throw new BadRequestAlertException("A new role cannot already have an ID", ENTITY_NAME, "idexists");
        }
        Role result = roleService.save(role);
        return ResponseEntity
            .created(new URI("/api/roles/" + result.getId()))
            .headers(HeaderUtil.createEntityCreationAlert(applicationName, true, ENTITY_NAME, result.getId().toString()))
            .body(result);
    }

    @PostMapping("/roles")
    @Authorize
    public ResponseEntity<Role> createRole1(@RequestBody Role roleData) {
        String roleName = roleData.getName();
        String roleDesc = roleData.getDescription();
        RoleRepresentation newRole = new RoleRepresentation();
        newRole.setName(roleName);
        newRole.setDescription(roleDesc);
        keycloak.realm("google").roles().create(newRole);
        String id = newRole.getId();
        Role result = new Role(roleName, roleDesc, id);
        return ResponseEntity.ok(result);
    }

    /**
     * {@code PUT  /roles/:id} : Updates an existing role.
     *
     * @param id the id of the role to save.
     * @param role the role to update.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the updated role,
     * or with status {@code 400 (Bad Request)} if the role is not valid,
     * or with status {@code 500 (Internal Server Error)} if the role couldn't be updated.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    // @PutMapping("/roles/{id}")
    public ResponseEntity<Role> updateRole(@PathVariable(value = "id", required = false) final String id, @Valid @RequestBody Role role)
        throws URISyntaxException {
        log.debug("REST request to update Role : {}, {}", id, role);
        /* if (role.getId() == null) {
            throw new BadRequestAlertException("Invalid id", ENTITY_NAME, "idnull");
        }
        if (!Objects.equals(id, role.getIdKeycloak())) {
            throw new BadRequestAlertException("Invalid ID", ENTITY_NAME, "idinvalid");
        }*/

        Map<String, String> roleData = new HashMap<>();
        roleData.put("name", role.getName());
        roleData.put("desription", role.getDescription());
        // roleData.put("id", role.getIdKeycloak());
        // UserController.updateRole(id,roleData);

        Role result = roleService.update(role);
        return ResponseEntity
            .ok()
            .headers(HeaderUtil.createEntityUpdateAlert(applicationName, true, ENTITY_NAME, role.getIdKeycloak().toString()))
            .body(result);
    }

    /**
     * {@code PATCH  /roles/:id} : Partial updates given fields of an existing role, field will ignore if it is null
     *
     * @param id the id of the role to save.
     * @param role the role to update.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the updated role,
     * or with status {@code 400 (Bad Request)} if the role is not valid,
     * or with status {@code 404 (Not Found)} if the role is not found,
     * or with status {@code 500 (Internal Server Error)} if the role couldn't be updated.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @PatchMapping(value = "/roles/{id}", consumes = { "application/json", "application/merge-patch+json" })
    public ResponseEntity<Role> partialUpdateRole(
        @PathVariable(value = "id", required = false) final Long id,
        @NotNull @RequestBody Role role
    ) throws URISyntaxException {
        log.debug("REST request to partial update Role partially : {}, {}", id, role);
        if (role.getId() == null) {
            throw new BadRequestAlertException("Invalid id", ENTITY_NAME, "idnull");
        }
        if (!Objects.equals(id, role.getId())) {
            throw new BadRequestAlertException("Invalid ID", ENTITY_NAME, "idinvalid");
        }

        if (!roleRepository.existsById(id)) {
            throw new BadRequestAlertException("Entity not found", ENTITY_NAME, "idnotfound");
        }

        Optional<Role> result = roleService.partialUpdate(role);

        return ResponseUtil.wrapOrNotFound(
            result,
            HeaderUtil.createEntityUpdateAlert(applicationName, true, ENTITY_NAME, role.getId().toString())
        );
    }

    /**
     * {@code GET  /roles} : get all the roles.
     *
     * @param pageable the pagination information.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and the list of roles in body.
     */
    // @GetMapping("/roles")
    //out of service
    public ResponseEntity<List<Role>> getAllRoles(@org.springdoc.api.annotations.ParameterObject Pageable pageable) {
        log.debug("REST request to get a page of Roles");
        Page<Role> page = roleService.findAll(pageable);
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), page);
        return ResponseEntity.ok().headers(headers).body(page.getContent());
    }

    @GetMapping("/roles")
    @Authorize
    public List<Map<String, String>> getRolesNameDesc() {
        RealmResource realmResource = keycloak.realm("google");
        List<RoleRepresentation> roles = realmResource.roles().list();
        List<Map<String, String>> result = new ArrayList<>();
        for (RoleRepresentation role : roles) {
            Map<String, String> roleMap = new HashMap<>();
            roleMap.put("name", role.getName());
            roleMap.put("description", role.getDescription());
            roleMap.put("id", role.getId());
            result.add(roleMap);
        }
        return result;
    }

    /**
     * {@code GET  /roles/:id} : get the "id" role.
     *
     * //@param id the id of the role to retrieve.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the role, or with status {@code 404 (Not Found)}.
     */
    @GetMapping("/roles/{id}")
    public ResponseEntity<Role> getRole(@PathVariable(value = "id") String roleId) {
        log.debug("REST request to get Role : {}", roleId);
        // Optional<Role> role = roleService.findOne(id);
        // return ResponseUtil.wrapOrNotFound(role);
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        String name = role.getName();
        String desc = role.getDescription();
        String idKeycloak = role.getId();
        Role rol = new Role(name, desc, idKeycloak);
        return ResponseEntity.ok(rol);
    }
    /**
     * {@code DELETE  /roles/:id} : delete the "id" role.
     *
     * @param id the id of the role to delete.
     * @return the {@link ResponseEntity} with status {@code 204 (NO_CONTENT)}.
     */

    /*@DeleteMapping("/roles/{id}")
    public ResponseEntity<Void> deleteRole(@PathVariable String roleId) {
        log.debug("REST request to delete Role : {}", roleId);
       // roleService.delete(id);
        RolesResource rolesResource = keycloak.realm("google").roles();
        //RoleRepresentation role = rolesResource.get(roleId).toRepresentation();
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        ResponseEntity<RoleRepresentation> rol = UserController.getRoleById(roleId);
        String roleName = rol.getBody().getName();
        ResponseEntity<String> del = UserController.deleteRoleByName(Collections.singletonMap("roleName", roleName));
        return ResponseEntity
            .noContent()
            .headers(HeaderUtil.createEntityDeletionAlert(applicationName, true, ENTITY_NAME, roleId.toString()))
            .build();
    }*/

}
