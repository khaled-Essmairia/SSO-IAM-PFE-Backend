package com.xtensus.passosyf.web.rest;

import com.xtensus.passosyf.domain.Group;
import com.xtensus.passosyf.repository.GroupRepository;
import com.xtensus.passosyf.service.GroupService;
import com.xtensus.passosyf.web.Authorize;
import com.xtensus.passosyf.web.rest.errors.BadRequestAlertException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.GroupRepresentation;
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
 * REST controller for managing {@link com.xtensus.passosyf.domain.Group}.
 */
@RestController
@RequestMapping("/api")
public class GroupResource {

    private final Logger log = LoggerFactory.getLogger(GroupResource.class);

    private static final String ENTITY_NAME = "group";

    @Value("${jhipster.clientApp.name}")
    private String applicationName;

    private final GroupService groupService;

    private final GroupRepository groupRepository;

    public GroupResource(GroupService groupService, GroupRepository groupRepository) {
        this.groupService = groupService;
        this.groupRepository = groupRepository;
    }

    /**
     * {@code POST  /groups} : Create a new group.
     *
     * @param group the group to create.
     * @return the {@link ResponseEntity} with status {@code 201 (Created)} and with body the new group, or with status {@code 400 (Bad Request)} if the group has already an ID.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @PostMapping("/groups1")
    public ResponseEntity<Group> createGroup1(@Valid @RequestBody Group group) throws URISyntaxException {
        log.debug("REST request to save Group : {}", group);
        if (group.getId() != null) {
            throw new BadRequestAlertException("A new group cannot already have an ID", ENTITY_NAME, "idexists");
        }
        Group result = groupService.save(group);
        return ResponseEntity
            .created(new URI("/api/groups/" + result.getId()))
            .headers(HeaderUtil.createEntityCreationAlert(applicationName, true, ENTITY_NAME, result.getId().toString()))
            .body(result);
    }

    @Authorize
    @PostMapping("/groups")
    public ResponseEntity<Group> createGroup(@Valid @RequestBody Group group) throws URISyntaxException {
        log.debug("REST request to save Group : {}", group);
        if (group.getId() != null) {
            throw new BadRequestAlertException("A new group cannot already have an ID", ENTITY_NAME, "idexists");
        }

        GroupRepresentation newGroupRepresentation = new GroupRepresentation();
        newGroupRepresentation.setName(group.getName());
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("description", Collections.singletonList(group.getDescription()));
        newGroupRepresentation.setAttributes(attributes);
        keycloak.realm("google").groups().add(newGroupRepresentation);
        Group newGroup = new Group();
        //Long groupId = Long.parseLong(groupIdString);
        newGroup.setIdKeycloak(newGroupRepresentation.getId());
        newGroup.setName(newGroupRepresentation.getName());
        newGroup.setDescription(newGroupRepresentation.getAttributes().get("description").get(0));

        return ResponseEntity
            .created(new URI("/api/groups/" + newGroup.getIdKeycloak()))
            .headers(HeaderUtil.createEntityCreationAlert(applicationName, true, ENTITY_NAME, newGroup.getIdKeycloak()))
            .body(newGroup);
    }

    /**
     * {@code PUT  /groups/:id} : Updates an existing group.
     *
     * @param id the id of the group to save.
     * @param group the group to update.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the updated group,
     * or with status {@code 400 (Bad Request)} if the group is not valid,
     * or with status {@code 500 (Internal Server Error)} if the group couldn't be updated.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @Authorize
    @PutMapping("/groups/{id}")
    public ResponseEntity<Group> updateGroup(
        @PathVariable(value = "id", required = false) final String id,
        @Valid @RequestBody Group group1
    ) throws URISyntaxException {
        log.debug("REST request to update Group : {}, {}", id, group1);
        if (group1.getIdKeycloak() == null) {
            throw new BadRequestAlertException("Invalid id", ENTITY_NAME, "idnull");
        }
        if (!Objects.equals(id, group1.getIdKeycloak())) {
            throw new BadRequestAlertException("Invalid ID", ENTITY_NAME, "idinvalid");
        }
        // Group result = groupService.update(group1);
        GroupRepresentation group = keycloak.realm("google").groups().group(id).toRepresentation();
        String groupName = group1.getName();
        if (groupName != null && !groupName.isEmpty()) {
            group.setName(groupName);
        }

        String groupDescription = group1.getDescription();
        if (groupDescription != null && !groupDescription.isEmpty()) {
            group.setAttributes(Collections.singletonMap("description", Arrays.asList(groupDescription)));
        }
        keycloak.realm("google").groups().group(id).update(group);
        return ResponseEntity
            .ok()
            .headers(HeaderUtil.createEntityUpdateAlert(applicationName, true, ENTITY_NAME, group1.getId().toString()))
            .body(group1);
    }

    /**
     * {@code PATCH  /groups/:id} : Partial updates given fields of an existing group, field will ignore if it is null
     *
     * @param id the id of the group to save.
     * @param group the group to update.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the updated group,
     * or with status {@code 400 (Bad Request)} if the group is not valid,
     * or with status {@code 404 (Not Found)} if the group is not found,
     * or with status {@code 500 (Internal Server Error)} if the group couldn't be updated.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @Authorize
    @PatchMapping(value = "/groups/{id}", consumes = { "application/json", "application/merge-patch+json" })
    public ResponseEntity<Group> partialUpdateGroup(
        @PathVariable(value = "id", required = false) final Long id,
        @NotNull @RequestBody Group group
    ) throws URISyntaxException {
        log.debug("REST request to partial update Group partially : {}, {}", id, group);
        if (group.getIdKeycloak() == null) {
            throw new BadRequestAlertException("Invalid id", ENTITY_NAME, "idnull");
        }
        if (!Objects.equals(id, group.getIdKeycloak())) {
            throw new BadRequestAlertException("Invalid ID", ENTITY_NAME, "idinvalid");
        }

        if (!groupRepository.existsById(id)) {
            throw new BadRequestAlertException("Entity not found", ENTITY_NAME, "idnotfound");
        }

        Optional<Group> result = groupService.partialUpdate(group);

        return ResponseUtil.wrapOrNotFound(
            result,
            HeaderUtil.createEntityUpdateAlert(applicationName, true, ENTITY_NAME, group.getId().toString())
        );
    }

    @Autowired
    private Keycloak keycloak;

    @Authorize
    @GetMapping("/groups")
    /* public ResponseEntity<List<Group>> getAllGroups(@org.springdoc.api.annotations.ParameterObject Pageable pageable) {
        log.debug("REST request to get a page of Groups");
        Page<Group> page = groupService.findAll(pageable);
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), page);
        return ResponseEntity.ok().headers(headers).body(page.getContent());
    }*/
    public List<Map<String, Object>> getAllGroupsWithAttributes() {
        // Get all groups in the realm
        List<GroupRepresentation> groups = keycloak.realm("google").groups().groups();

        // Create a list to store the attributes of each group
        List<Map<String, Object>> groupsWithAttributes = new ArrayList<>();

        // Iterate over the groups and retrieve their attributes
        for (GroupRepresentation group : groups) {
            // Get the group by ID
            GroupRepresentation groupRepresentation = keycloak.realm("google").groups().group(group.getId()).toRepresentation();

            // Create a map to store the group ID and attributes
            Map<String, Object> groupWithAttributes = new HashMap<>();
            groupWithAttributes.put("id", groupRepresentation.getId());
            groupWithAttributes.put("name", groupRepresentation.getName());
            //groupWithAttributes.put("attributes", groupRepresentation.getAttributes());
            // Retrieve the group's description attribute
            List<String> descriptionList = groupRepresentation.getAttributes().get("description");
            String description = descriptionList != null && !descriptionList.isEmpty() ? descriptionList.get(0) : "";
            groupWithAttributes.put("description", description);

            groupsWithAttributes.add(groupWithAttributes);
        }

        return groupsWithAttributes;
    }

    @GetMapping("/groups/{id}")
    public ResponseEntity<Group> getGroup(@PathVariable String id) {
        log.debug("REST request to get Group : {}", id);

        GroupRepresentation groupRepresentation = keycloak.realm("google").groups().group(id).toRepresentation();
        String name = groupRepresentation.getName();
        String desc = groupRepresentation.getAttributes().get("description").get(0);
        String idKeycloak = groupRepresentation.getId();
        Group group = new Group(name, desc, idKeycloak);

        return ResponseEntity.ok(group);
    }

    /**
     * {@code DELETE  /groups/:id} : delete the "id" group.
     *
     * @param id the id of the group to delete.
     * @return the {@link ResponseEntity} with status {@code 204 (NO_CONTENT)}.
     */
    @Authorize
    @DeleteMapping("/groups/{id}")
    public ResponseEntity<Void> deleteGroup(@PathVariable String id) {
        log.debug("REST request to delete Group : {}", id);
        //groupService.delete(id);
        keycloak.realm("google").groups().group(id).remove();
        return ResponseEntity
            .noContent()
            .headers(HeaderUtil.createEntityDeletionAlert(applicationName, true, ENTITY_NAME, id.toString()))
            .build();
    }
}
