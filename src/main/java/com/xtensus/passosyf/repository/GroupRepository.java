package com.xtensus.passosyf.repository;

import com.xtensus.passosyf.domain.Group;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;

/**
 * Spring Data JPA repository for the Group entity.
 */
@SuppressWarnings("unused")
@Repository
public interface GroupRepository extends JpaRepository<Group, Long> {}
