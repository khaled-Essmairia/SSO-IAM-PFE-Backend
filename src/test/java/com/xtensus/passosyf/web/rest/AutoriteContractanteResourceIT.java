package com.xtensus.passosyf.web.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.xtensus.passosyf.IntegrationTest;
import com.xtensus.passosyf.domain.AutoriteContractante;
import com.xtensus.passosyf.repository.AutoriteContractanteRepository;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/**
 * Integration tests for the {@link AutoriteContractanteResource} REST controller.
 */
@IntegrationTest
@AutoConfigureMockMvc
@WithMockUser
class AutoriteContractanteResourceIT {

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_LIBELLE = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_LIBELLE = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_INITIALE = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_INITIALE = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_RESPONSABLE = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_ADRESS_MAIL = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_ADRESS_MAIL = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_SITE_WEB = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_SITE_WEB = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_ADRESSE = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_ADRESSE = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_TELEPHONE = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_FAX = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_FAX = "BBBBBBBBBB";

    private static final String DEFAULT_AUTORITE_CONTRACTANTE_DESCRIPTION = "AAAAAAAAAA";
    private static final String UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION = "BBBBBBBBBB";

    private static final String ENTITY_API_URL = "/api/autorite-contractantes";
    private static final String ENTITY_API_URL_ID = ENTITY_API_URL + "/{id}";

    private static Random random = new Random();
    private static AtomicLong count = new AtomicLong(random.nextInt() + (2 * Integer.MAX_VALUE));

    @Autowired
    private AutoriteContractanteRepository autoriteContractanteRepository;

    @Autowired
    private EntityManager em;

    @Autowired
    private MockMvc restAutoriteContractanteMockMvc;

    private AutoriteContractante autoriteContractante;

    /**
     * Create an entity for this test.
     *
     * This is a static method, as tests for other entities might also need it,
     * if they test an entity which requires the current entity.
     */
    public static AutoriteContractante createEntity(EntityManager em) {
        AutoriteContractante autoriteContractante = new AutoriteContractante()
            .autoriteContractanteLibelle(DEFAULT_AUTORITE_CONTRACTANTE_LIBELLE)
            .autoriteContractanteInitiale(DEFAULT_AUTORITE_CONTRACTANTE_INITIALE)
            .autoriteContractanteResponsable(DEFAULT_AUTORITE_CONTRACTANTE_RESPONSABLE)
            .autoriteContractanteAdressMail(DEFAULT_AUTORITE_CONTRACTANTE_ADRESS_MAIL)
            .autoriteContractanteSiteWeb(DEFAULT_AUTORITE_CONTRACTANTE_SITE_WEB)
            .autoriteContractanteAdresse(DEFAULT_AUTORITE_CONTRACTANTE_ADRESSE)
            .autoriteContractanteTelephone(DEFAULT_AUTORITE_CONTRACTANTE_TELEPHONE)
            .autoriteContractanteFax(DEFAULT_AUTORITE_CONTRACTANTE_FAX)
            .autoriteContractanteDescription(DEFAULT_AUTORITE_CONTRACTANTE_DESCRIPTION);
        return autoriteContractante;
    }

    /**
     * Create an updated entity for this test.
     *
     * This is a static method, as tests for other entities might also need it,
     * if they test an entity which requires the current entity.
     */
    public static AutoriteContractante createUpdatedEntity(EntityManager em) {
        AutoriteContractante autoriteContractante = new AutoriteContractante()
            .autoriteContractanteLibelle(UPDATED_AUTORITE_CONTRACTANTE_LIBELLE)
            .autoriteContractanteInitiale(UPDATED_AUTORITE_CONTRACTANTE_INITIALE)
            .autoriteContractanteResponsable(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE)
            .autoriteContractanteAdressMail(UPDATED_AUTORITE_CONTRACTANTE_ADRESS_MAIL)
            .autoriteContractanteSiteWeb(UPDATED_AUTORITE_CONTRACTANTE_SITE_WEB)
            .autoriteContractanteAdresse(UPDATED_AUTORITE_CONTRACTANTE_ADRESSE)
            .autoriteContractanteTelephone(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE)
            .autoriteContractanteFax(UPDATED_AUTORITE_CONTRACTANTE_FAX)
            .autoriteContractanteDescription(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);
        return autoriteContractante;
    }

    @BeforeEach
    public void initTest() {
        autoriteContractante = createEntity(em);
    }

    @Test
    @Transactional
    void createAutoriteContractante() throws Exception {
        int databaseSizeBeforeCreate = autoriteContractanteRepository.findAll().size();
        // Create the AutoriteContractante
        restAutoriteContractanteMockMvc
            .perform(
                post(ENTITY_API_URL)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isCreated());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeCreate + 1);
        AutoriteContractante testAutoriteContractante = autoriteContractanteList.get(autoriteContractanteList.size() - 1);
        assertThat(testAutoriteContractante.getAutoriteContractanteLibelle()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_LIBELLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteInitiale()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_INITIALE);
        assertThat(testAutoriteContractante.getAutoriteContractanteResponsable()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_RESPONSABLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdressMail()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_ADRESS_MAIL);
        assertThat(testAutoriteContractante.getAutoriteContractanteSiteWeb()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_SITE_WEB);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdresse()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_ADRESSE);
        assertThat(testAutoriteContractante.getAutoriteContractanteTelephone()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_TELEPHONE);
        assertThat(testAutoriteContractante.getAutoriteContractanteFax()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_FAX);
        assertThat(testAutoriteContractante.getAutoriteContractanteDescription()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_DESCRIPTION);
    }

    @Test
    @Transactional
    void createAutoriteContractanteWithExistingId() throws Exception {
        // Create the AutoriteContractante with an existing ID
        autoriteContractante.setId(1L);

        int databaseSizeBeforeCreate = autoriteContractanteRepository.findAll().size();

        // An entity with an existing ID cannot be created, so this API call must fail
        restAutoriteContractanteMockMvc
            .perform(
                post(ENTITY_API_URL)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isBadRequest());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeCreate);
    }

    @Test
    @Transactional
    void getAllAutoriteContractantes() throws Exception {
        // Initialize the database
        autoriteContractanteRepository.saveAndFlush(autoriteContractante);

        // Get all the autoriteContractanteList
        restAutoriteContractanteMockMvc
            .perform(get(ENTITY_API_URL + "?sort=id,desc"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.[*].id").value(hasItem(autoriteContractante.getId().intValue())))
            .andExpect(jsonPath("$.[*].autoriteContractanteLibelle").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_LIBELLE)))
            .andExpect(jsonPath("$.[*].autoriteContractanteInitiale").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_INITIALE)))
            .andExpect(jsonPath("$.[*].autoriteContractanteResponsable").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_RESPONSABLE)))
            .andExpect(jsonPath("$.[*].autoriteContractanteAdressMail").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_ADRESS_MAIL)))
            .andExpect(jsonPath("$.[*].autoriteContractanteSiteWeb").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_SITE_WEB)))
            .andExpect(jsonPath("$.[*].autoriteContractanteAdresse").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_ADRESSE)))
            .andExpect(jsonPath("$.[*].autoriteContractanteTelephone").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_TELEPHONE)))
            .andExpect(jsonPath("$.[*].autoriteContractanteFax").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_FAX)))
            .andExpect(jsonPath("$.[*].autoriteContractanteDescription").value(hasItem(DEFAULT_AUTORITE_CONTRACTANTE_DESCRIPTION)));
    }

    @Test
    @Transactional
    void getAutoriteContractante() throws Exception {
        // Initialize the database
        autoriteContractanteRepository.saveAndFlush(autoriteContractante);

        // Get the autoriteContractante
        restAutoriteContractanteMockMvc
            .perform(get(ENTITY_API_URL_ID, autoriteContractante.getId()))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.id").value(autoriteContractante.getId().intValue()))
            .andExpect(jsonPath("$.autoriteContractanteLibelle").value(DEFAULT_AUTORITE_CONTRACTANTE_LIBELLE))
            .andExpect(jsonPath("$.autoriteContractanteInitiale").value(DEFAULT_AUTORITE_CONTRACTANTE_INITIALE))
            .andExpect(jsonPath("$.autoriteContractanteResponsable").value(DEFAULT_AUTORITE_CONTRACTANTE_RESPONSABLE))
            .andExpect(jsonPath("$.autoriteContractanteAdressMail").value(DEFAULT_AUTORITE_CONTRACTANTE_ADRESS_MAIL))
            .andExpect(jsonPath("$.autoriteContractanteSiteWeb").value(DEFAULT_AUTORITE_CONTRACTANTE_SITE_WEB))
            .andExpect(jsonPath("$.autoriteContractanteAdresse").value(DEFAULT_AUTORITE_CONTRACTANTE_ADRESSE))
            .andExpect(jsonPath("$.autoriteContractanteTelephone").value(DEFAULT_AUTORITE_CONTRACTANTE_TELEPHONE))
            .andExpect(jsonPath("$.autoriteContractanteFax").value(DEFAULT_AUTORITE_CONTRACTANTE_FAX))
            .andExpect(jsonPath("$.autoriteContractanteDescription").value(DEFAULT_AUTORITE_CONTRACTANTE_DESCRIPTION));
    }

    @Test
    @Transactional
    void getNonExistingAutoriteContractante() throws Exception {
        // Get the autoriteContractante
        restAutoriteContractanteMockMvc.perform(get(ENTITY_API_URL_ID, Long.MAX_VALUE)).andExpect(status().isNotFound());
    }

    @Test
    @Transactional
    void putExistingAutoriteContractante() throws Exception {
        // Initialize the database
        autoriteContractanteRepository.saveAndFlush(autoriteContractante);

        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();

        // Update the autoriteContractante
        AutoriteContractante updatedAutoriteContractante = autoriteContractanteRepository.findById(autoriteContractante.getId()).get();
        // Disconnect from session so that the updates on updatedAutoriteContractante are not directly saved in db
        em.detach(updatedAutoriteContractante);
        updatedAutoriteContractante
            .autoriteContractanteLibelle(UPDATED_AUTORITE_CONTRACTANTE_LIBELLE)
            .autoriteContractanteInitiale(UPDATED_AUTORITE_CONTRACTANTE_INITIALE)
            .autoriteContractanteResponsable(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE)
            .autoriteContractanteAdressMail(UPDATED_AUTORITE_CONTRACTANTE_ADRESS_MAIL)
            .autoriteContractanteSiteWeb(UPDATED_AUTORITE_CONTRACTANTE_SITE_WEB)
            .autoriteContractanteAdresse(UPDATED_AUTORITE_CONTRACTANTE_ADRESSE)
            .autoriteContractanteTelephone(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE)
            .autoriteContractanteFax(UPDATED_AUTORITE_CONTRACTANTE_FAX)
            .autoriteContractanteDescription(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);

        restAutoriteContractanteMockMvc
            .perform(
                put(ENTITY_API_URL_ID, updatedAutoriteContractante.getId())
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(TestUtil.convertObjectToJsonBytes(updatedAutoriteContractante))
            )
            .andExpect(status().isOk());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
        AutoriteContractante testAutoriteContractante = autoriteContractanteList.get(autoriteContractanteList.size() - 1);
        assertThat(testAutoriteContractante.getAutoriteContractanteLibelle()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_LIBELLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteInitiale()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_INITIALE);
        assertThat(testAutoriteContractante.getAutoriteContractanteResponsable()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdressMail()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_ADRESS_MAIL);
        assertThat(testAutoriteContractante.getAutoriteContractanteSiteWeb()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_SITE_WEB);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdresse()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_ADRESSE);
        assertThat(testAutoriteContractante.getAutoriteContractanteTelephone()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE);
        assertThat(testAutoriteContractante.getAutoriteContractanteFax()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_FAX);
        assertThat(testAutoriteContractante.getAutoriteContractanteDescription()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);
    }

    @Test
    @Transactional
    void putNonExistingAutoriteContractante() throws Exception {
        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();
        autoriteContractante.setId(count.incrementAndGet());

        // If the entity doesn't have an ID, it will throw BadRequestAlertException
        restAutoriteContractanteMockMvc
            .perform(
                put(ENTITY_API_URL_ID, autoriteContractante.getId())
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isBadRequest());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
    }

    @Test
    @Transactional
    void putWithIdMismatchAutoriteContractante() throws Exception {
        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();
        autoriteContractante.setId(count.incrementAndGet());

        // If url ID doesn't match entity ID, it will throw BadRequestAlertException
        restAutoriteContractanteMockMvc
            .perform(
                put(ENTITY_API_URL_ID, count.incrementAndGet())
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isBadRequest());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
    }

    @Test
    @Transactional
    void putWithMissingIdPathParamAutoriteContractante() throws Exception {
        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();
        autoriteContractante.setId(count.incrementAndGet());

        // If url ID doesn't match entity ID, it will throw BadRequestAlertException
        restAutoriteContractanteMockMvc
            .perform(
                put(ENTITY_API_URL)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isMethodNotAllowed());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
    }

    @Test
    @Transactional
    void partialUpdateAutoriteContractanteWithPatch() throws Exception {
        // Initialize the database
        autoriteContractanteRepository.saveAndFlush(autoriteContractante);

        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();

        // Update the autoriteContractante using partial update
        AutoriteContractante partialUpdatedAutoriteContractante = new AutoriteContractante();
        partialUpdatedAutoriteContractante.setId(autoriteContractante.getId());

        partialUpdatedAutoriteContractante
            .autoriteContractanteInitiale(UPDATED_AUTORITE_CONTRACTANTE_INITIALE)
            .autoriteContractanteResponsable(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE)
            .autoriteContractanteTelephone(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE)
            .autoriteContractanteDescription(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);

        restAutoriteContractanteMockMvc
            .perform(
                patch(ENTITY_API_URL_ID, partialUpdatedAutoriteContractante.getId())
                    .with(csrf())
                    .contentType("application/merge-patch+json")
                    .content(TestUtil.convertObjectToJsonBytes(partialUpdatedAutoriteContractante))
            )
            .andExpect(status().isOk());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
        AutoriteContractante testAutoriteContractante = autoriteContractanteList.get(autoriteContractanteList.size() - 1);
        assertThat(testAutoriteContractante.getAutoriteContractanteLibelle()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_LIBELLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteInitiale()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_INITIALE);
        assertThat(testAutoriteContractante.getAutoriteContractanteResponsable()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdressMail()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_ADRESS_MAIL);
        assertThat(testAutoriteContractante.getAutoriteContractanteSiteWeb()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_SITE_WEB);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdresse()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_ADRESSE);
        assertThat(testAutoriteContractante.getAutoriteContractanteTelephone()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE);
        assertThat(testAutoriteContractante.getAutoriteContractanteFax()).isEqualTo(DEFAULT_AUTORITE_CONTRACTANTE_FAX);
        assertThat(testAutoriteContractante.getAutoriteContractanteDescription()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);
    }

    @Test
    @Transactional
    void fullUpdateAutoriteContractanteWithPatch() throws Exception {
        // Initialize the database
        autoriteContractanteRepository.saveAndFlush(autoriteContractante);

        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();

        // Update the autoriteContractante using partial update
        AutoriteContractante partialUpdatedAutoriteContractante = new AutoriteContractante();
        partialUpdatedAutoriteContractante.setId(autoriteContractante.getId());

        partialUpdatedAutoriteContractante
            .autoriteContractanteLibelle(UPDATED_AUTORITE_CONTRACTANTE_LIBELLE)
            .autoriteContractanteInitiale(UPDATED_AUTORITE_CONTRACTANTE_INITIALE)
            .autoriteContractanteResponsable(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE)
            .autoriteContractanteAdressMail(UPDATED_AUTORITE_CONTRACTANTE_ADRESS_MAIL)
            .autoriteContractanteSiteWeb(UPDATED_AUTORITE_CONTRACTANTE_SITE_WEB)
            .autoriteContractanteAdresse(UPDATED_AUTORITE_CONTRACTANTE_ADRESSE)
            .autoriteContractanteTelephone(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE)
            .autoriteContractanteFax(UPDATED_AUTORITE_CONTRACTANTE_FAX)
            .autoriteContractanteDescription(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);

        restAutoriteContractanteMockMvc
            .perform(
                patch(ENTITY_API_URL_ID, partialUpdatedAutoriteContractante.getId())
                    .with(csrf())
                    .contentType("application/merge-patch+json")
                    .content(TestUtil.convertObjectToJsonBytes(partialUpdatedAutoriteContractante))
            )
            .andExpect(status().isOk());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
        AutoriteContractante testAutoriteContractante = autoriteContractanteList.get(autoriteContractanteList.size() - 1);
        assertThat(testAutoriteContractante.getAutoriteContractanteLibelle()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_LIBELLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteInitiale()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_INITIALE);
        assertThat(testAutoriteContractante.getAutoriteContractanteResponsable()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_RESPONSABLE);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdressMail()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_ADRESS_MAIL);
        assertThat(testAutoriteContractante.getAutoriteContractanteSiteWeb()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_SITE_WEB);
        assertThat(testAutoriteContractante.getAutoriteContractanteAdresse()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_ADRESSE);
        assertThat(testAutoriteContractante.getAutoriteContractanteTelephone()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_TELEPHONE);
        assertThat(testAutoriteContractante.getAutoriteContractanteFax()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_FAX);
        assertThat(testAutoriteContractante.getAutoriteContractanteDescription()).isEqualTo(UPDATED_AUTORITE_CONTRACTANTE_DESCRIPTION);
    }

    @Test
    @Transactional
    void patchNonExistingAutoriteContractante() throws Exception {
        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();
        autoriteContractante.setId(count.incrementAndGet());

        // If the entity doesn't have an ID, it will throw BadRequestAlertException
        restAutoriteContractanteMockMvc
            .perform(
                patch(ENTITY_API_URL_ID, autoriteContractante.getId())
                    .with(csrf())
                    .contentType("application/merge-patch+json")
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isBadRequest());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
    }

    @Test
    @Transactional
    void patchWithIdMismatchAutoriteContractante() throws Exception {
        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();
        autoriteContractante.setId(count.incrementAndGet());

        // If url ID doesn't match entity ID, it will throw BadRequestAlertException
        restAutoriteContractanteMockMvc
            .perform(
                patch(ENTITY_API_URL_ID, count.incrementAndGet())
                    .with(csrf())
                    .contentType("application/merge-patch+json")
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isBadRequest());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
    }

    @Test
    @Transactional
    void patchWithMissingIdPathParamAutoriteContractante() throws Exception {
        int databaseSizeBeforeUpdate = autoriteContractanteRepository.findAll().size();
        autoriteContractante.setId(count.incrementAndGet());

        // If url ID doesn't match entity ID, it will throw BadRequestAlertException
        restAutoriteContractanteMockMvc
            .perform(
                patch(ENTITY_API_URL)
                    .with(csrf())
                    .contentType("application/merge-patch+json")
                    .content(TestUtil.convertObjectToJsonBytes(autoriteContractante))
            )
            .andExpect(status().isMethodNotAllowed());

        // Validate the AutoriteContractante in the database
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeUpdate);
    }

    @Test
    @Transactional
    void deleteAutoriteContractante() throws Exception {
        // Initialize the database
        autoriteContractanteRepository.saveAndFlush(autoriteContractante);

        int databaseSizeBeforeDelete = autoriteContractanteRepository.findAll().size();

        // Delete the autoriteContractante
        restAutoriteContractanteMockMvc
            .perform(delete(ENTITY_API_URL_ID, autoriteContractante.getId()).with(csrf()).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isNoContent());

        // Validate the database contains one less item
        List<AutoriteContractante> autoriteContractanteList = autoriteContractanteRepository.findAll();
        assertThat(autoriteContractanteList).hasSize(databaseSizeBeforeDelete - 1);
    }
}
