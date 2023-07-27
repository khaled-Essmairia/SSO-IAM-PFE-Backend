package com.xtensus.passosyf.web.rest;

import com.xtensus.passosyf.domain.AutoriteContractante;
import com.xtensus.passosyf.repository.AutoriteContractanteRepository;
import com.xtensus.passosyf.web.Authorize;
import com.xtensus.passosyf.web.rest.errors.BadRequestAlertException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import tech.jhipster.web.util.HeaderUtil;
import tech.jhipster.web.util.PaginationUtil;
import tech.jhipster.web.util.ResponseUtil;

/**
 * REST controller for managing {@link com.xtensus.passosyf.domain.AutoriteContractante}.
 */
@RestController
@RequestMapping("/api")
@Transactional
public class AutoriteContractanteResource {

    private final Logger log = LoggerFactory.getLogger(AutoriteContractanteResource.class);

    private static final String ENTITY_NAME = "autoriteContractante";

    @Value("${jhipster.clientApp.name}")
    private String applicationName;

    private final AutoriteContractanteRepository autoriteContractanteRepository;

    public AutoriteContractanteResource(AutoriteContractanteRepository autoriteContractanteRepository) {
        this.autoriteContractanteRepository = autoriteContractanteRepository;
    }

    /**
     * {@code POST  /autorite-contractantes} : Create a new autoriteContractante.
     *
     * @param autoriteContractante the autoriteContractante to create.
     * @return the {@link ResponseEntity} with status {@code 201 (Created)} and with body the new autoriteContractante, or with status {@code 400 (Bad Request)} if the autoriteContractante has already an ID.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @Authorize
    @PostMapping("/autorite-contractantes")
    public ResponseEntity<AutoriteContractante> createAutoriteContractante(@RequestBody AutoriteContractante autoriteContractante)
        throws URISyntaxException {
        log.debug("REST request to save AutoriteContractante : {}", autoriteContractante);
        if (autoriteContractante.getId() != null) {
            throw new BadRequestAlertException("A new autoriteContractante cannot already have an ID", ENTITY_NAME, "idexists");
        }
        AutoriteContractante result = autoriteContractanteRepository.save(autoriteContractante);
        return ResponseEntity
            .created(new URI("/api/autorite-contractantes/" + result.getId()))
            .headers(HeaderUtil.createEntityCreationAlert(applicationName, true, ENTITY_NAME, result.getId().toString()))
            .body(result);
    }

    /**
     * {@code PUT  /autorite-contractantes/:id} : Updates an existing autoriteContractante.
     *
     * @param id the id of the autoriteContractante to save.
     * @param autoriteContractante the autoriteContractante to update.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the updated autoriteContractante,
     * or with status {@code 400 (Bad Request)} if the autoriteContractante is not valid,
     * or with status {@code 500 (Internal Server Error)} if the autoriteContractante couldn't be updated.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @Authorize
    @PutMapping("/autorite-contractantes/{id}")
    public ResponseEntity<AutoriteContractante> updateAutoriteContractante(
        @PathVariable(value = "id", required = false) final Long id,
        @RequestBody AutoriteContractante autoriteContractante
    ) throws URISyntaxException {
        log.debug("REST request to update AutoriteContractante : {}, {}", id, autoriteContractante);
        if (autoriteContractante.getId() == null) {
            throw new BadRequestAlertException("Invalid id", ENTITY_NAME, "idnull");
        }
        if (!Objects.equals(id, autoriteContractante.getId())) {
            throw new BadRequestAlertException("Invalid ID", ENTITY_NAME, "idinvalid");
        }

        if (!autoriteContractanteRepository.existsById(id)) {
            throw new BadRequestAlertException("Entity not found", ENTITY_NAME, "idnotfound");
        }

        AutoriteContractante result = autoriteContractanteRepository.save(autoriteContractante);
        return ResponseEntity
            .ok()
            .headers(HeaderUtil.createEntityUpdateAlert(applicationName, true, ENTITY_NAME, autoriteContractante.getId().toString()))
            .body(result);
    }

    /**
     * {@code PATCH  /autorite-contractantes/:id} : Partial updates given fields of an existing autoriteContractante, field will ignore if it is null
     *
     * @param id the id of the autoriteContractante to save.
     * @param autoriteContractante the autoriteContractante to update.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the updated autoriteContractante,
     * or with status {@code 400 (Bad Request)} if the autoriteContractante is not valid,
     * or with status {@code 404 (Not Found)} if the autoriteContractante is not found,
     * or with status {@code 500 (Internal Server Error)} if the autoriteContractante couldn't be updated.
     * @throws URISyntaxException if the Location URI syntax is incorrect.
     */
    @Authorize
    @PatchMapping(value = "/autorite-contractantes/{id}", consumes = { "application/json", "application/merge-patch+json" })
    public ResponseEntity<AutoriteContractante> partialUpdateAutoriteContractante(
        @PathVariable(value = "id", required = false) final Long id,
        @RequestBody AutoriteContractante autoriteContractante
    ) throws URISyntaxException {
        log.debug("REST request to partial update AutoriteContractante partially : {}, {}", id, autoriteContractante);
        if (autoriteContractante.getId() == null) {
            throw new BadRequestAlertException("Invalid id", ENTITY_NAME, "idnull");
        }
        if (!Objects.equals(id, autoriteContractante.getId())) {
            throw new BadRequestAlertException("Invalid ID", ENTITY_NAME, "idinvalid");
        }

        if (!autoriteContractanteRepository.existsById(id)) {
            throw new BadRequestAlertException("Entity not found", ENTITY_NAME, "idnotfound");
        }

        Optional<AutoriteContractante> result = autoriteContractanteRepository
            .findById(autoriteContractante.getId())
            .map(existingAutoriteContractante -> {
                if (autoriteContractante.getAutoriteContractanteLibelle() != null) {
                    existingAutoriteContractante.setAutoriteContractanteLibelle(autoriteContractante.getAutoriteContractanteLibelle());
                }
                if (autoriteContractante.getAutoriteContractanteInitiale() != null) {
                    existingAutoriteContractante.setAutoriteContractanteInitiale(autoriteContractante.getAutoriteContractanteInitiale());
                }
                if (autoriteContractante.getAutoriteContractanteResponsable() != null) {
                    existingAutoriteContractante.setAutoriteContractanteResponsable(
                        autoriteContractante.getAutoriteContractanteResponsable()
                    );
                }
                if (autoriteContractante.getAutoriteContractanteAdressMail() != null) {
                    existingAutoriteContractante.setAutoriteContractanteAdressMail(
                        autoriteContractante.getAutoriteContractanteAdressMail()
                    );
                }
                if (autoriteContractante.getAutoriteContractanteSiteWeb() != null) {
                    existingAutoriteContractante.setAutoriteContractanteSiteWeb(autoriteContractante.getAutoriteContractanteSiteWeb());
                }
                if (autoriteContractante.getAutoriteContractanteAdresse() != null) {
                    existingAutoriteContractante.setAutoriteContractanteAdresse(autoriteContractante.getAutoriteContractanteAdresse());
                }
                if (autoriteContractante.getAutoriteContractanteTelephone() != null) {
                    existingAutoriteContractante.setAutoriteContractanteTelephone(autoriteContractante.getAutoriteContractanteTelephone());
                }
                if (autoriteContractante.getAutoriteContractanteFax() != null) {
                    existingAutoriteContractante.setAutoriteContractanteFax(autoriteContractante.getAutoriteContractanteFax());
                }
                if (autoriteContractante.getAutoriteContractanteDescription() != null) {
                    existingAutoriteContractante.setAutoriteContractanteDescription(
                        autoriteContractante.getAutoriteContractanteDescription()
                    );
                }

                return existingAutoriteContractante;
            })
            .map(autoriteContractanteRepository::save);

        return ResponseUtil.wrapOrNotFound(
            result,
            HeaderUtil.createEntityUpdateAlert(applicationName, true, ENTITY_NAME, autoriteContractante.getId().toString())
        );
    }

    /**
     * {@code GET  /autorite-contractantes} : get all the autoriteContractantes.
     *
     * @param pageable the pagination information.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and the list of autoriteContractantes in body.
     */
    @Authorize
    @GetMapping("/autorite-contractantes")
    public ResponseEntity<List<AutoriteContractante>> getAllAutoriteContractantes(@org.springdoc.api.annotations.ParameterObject Pageable pageable
    ) {
        log.debug("REST request to get a page of AutoriteContractantes");
        Page<AutoriteContractante> page = autoriteContractanteRepository.findAll(pageable);
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), page);
        return ResponseEntity.ok().headers(headers).body(page.getContent());
    }


    /**
     * {@code GET  /autorite-contractantes/:id} : get the "id" autoriteContractante.
     *
     * @param id the id of the autoriteContractante to retrieve.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and with body the autoriteContractante, or with status {@code 404 (Not Found)}.
     */
    @GetMapping("/autorite-contractantes/{id}")
    public ResponseEntity<AutoriteContractante> getAutoriteContractante(@PathVariable Long id) {
        log.debug("REST request to get AutoriteContractante : {}", id);
        Optional<AutoriteContractante> autoriteContractante = autoriteContractanteRepository.findById(id);
        return ResponseUtil.wrapOrNotFound(autoriteContractante);
    }

    /**
     * {@code DELETE  /autorite-contractantes/:id} : delete the "id" autoriteContractante.
     *
     * @param id the id of the autoriteContractante to delete.
     * @return the {@link ResponseEntity} with status {@code 204 (NO_CONTENT)}.
     */
    @Authorize
    @DeleteMapping("/autorite-contractantes/{id}")
    public ResponseEntity<Void> deleteAutoriteContractante(@PathVariable Long id) {
        log.debug("REST request to delete AutoriteContractante : {}", id);
        autoriteContractanteRepository.deleteById(id);
        return ResponseEntity
            .noContent()
            .headers(HeaderUtil.createEntityDeletionAlert(applicationName, true, ENTITY_NAME, id.toString()))
            .build();
    }
}
