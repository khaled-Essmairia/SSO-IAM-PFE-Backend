package com.xtensus.passosyf.repository;

import com.xtensus.passosyf.domain.AutoriteContractante;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;

/**
 * Spring Data JPA repository for the AutoriteContractante entity.
 */
@SuppressWarnings("unused")
@Repository
public interface AutoriteContractanteRepository extends JpaRepository<AutoriteContractante, Long> {}
