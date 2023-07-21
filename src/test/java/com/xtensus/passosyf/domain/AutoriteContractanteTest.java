package com.xtensus.passosyf.domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.xtensus.passosyf.web.rest.TestUtil;
import org.junit.jupiter.api.Test;

class AutoriteContractanteTest {

    @Test
    void equalsVerifier() throws Exception {
        TestUtil.equalsVerifier(AutoriteContractante.class);
        AutoriteContractante autoriteContractante1 = new AutoriteContractante();
        autoriteContractante1.setId(1L);
        AutoriteContractante autoriteContractante2 = new AutoriteContractante();
        autoriteContractante2.setId(autoriteContractante1.getId());
        assertThat(autoriteContractante1).isEqualTo(autoriteContractante2);
        autoriteContractante2.setId(2L);
        assertThat(autoriteContractante1).isNotEqualTo(autoriteContractante2);
        autoriteContractante1.setId(null);
        assertThat(autoriteContractante1).isNotEqualTo(autoriteContractante2);
    }
}
