package com.xtensus.passosyf.service;

import com.xtensus.passosyf.domain.Group;
import com.xtensus.passosyf.repository.GroupRepository;
import java.util.Optional;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service Implementation for managing {@link Group}.
 */
@Service
@Transactional
public class GroupService {

    private final Logger log = LoggerFactory.getLogger(GroupService.class);

    private final GroupRepository groupRepository;

    public GroupService(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    /**
     * Save a group.
     *
     * @param group the entity to save.
     * @return the persisted entity.
     */
    public Group save(Group group) {
        log.debug("Request to save Group : {}", group);
        return groupRepository.save(group);
    }

    /**
     * Update a group.
     *
     * @param group the entity to save.
     * @return the persisted entity.
     */
    public Group update(Group group) {
        log.debug("Request to update Group : {}", group);
        return groupRepository.save(group);
    }

    /**
     * Partially update a group.
     *
     * @param group the entity to update partially.
     * @return the persisted entity.
     */
    public Optional<Group> partialUpdate(Group group) {
        log.debug("Request to partially update Group : {}", group);

        return groupRepository
            .findById(group.getId())
            .map(existingGroup -> {
                if (group.getName() != null) {
                    existingGroup.setName(group.getName());
                }
                if (group.getDescription() != null) {
                    existingGroup.setDescription(group.getDescription());
                }

                return existingGroup;
            })
            .map(groupRepository::save);
    }

    @Autowired
    private Keycloak keycloak;

    public void partialUpdate(GroupRepresentation group) {
        log.debug("Request to partially update Group : {}", group);
        String groupId = group.getId();
        GroupResource groupResource = keycloak.realm("google").groups().group(groupId);
        GroupRepresentation existingGroup = groupResource.toRepresentation();
        if (group.getName() != null) {
            existingGroup.setName(group.getName());
        }
        if (group.getAttributes().get("description") != null && !group.getAttributes().get("description").isEmpty()) {
            existingGroup.getAttributes().put("description", group.getAttributes().get("description"));
        }
        groupResource.update(existingGroup);
    }

    /**
     * Get all the groups.
     *
     * @param pageable the pagination information.
     * @return the list of entities.
     */
    @Transactional(readOnly = true)
    public Page<Group> findAll(Pageable pageable) {
        log.debug("Request to get all Groups");
        return groupRepository.findAll(pageable);
    }

    /**
     * Get one group by id.
     *
     * @param id the id of the entity.
     * @return the entity.
     */
    @Transactional(readOnly = true)
    public Optional<Group> findOne(Long id) {
        log.debug("Request to get Group : {}", id);
        return groupRepository.findById(id);
    }

    /**
     * Delete the group by id.
     *
     * @param id the id of the entity.
     */
    public void delete(Long id) {
        log.debug("Request to delete Group : {}", id);
        groupRepository.deleteById(id);
    }
}
