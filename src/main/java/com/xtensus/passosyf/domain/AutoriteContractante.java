package com.xtensus.passosyf.domain;

import javax.persistence.*;
import java.io.Serializable;

/**
 * A AutoriteContractante.
 */
@Entity
@Table(name = "autorite_contractante")
@SuppressWarnings("common-java:DuplicatedBlocks")
public class AutoriteContractante implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "autorite_contractante_libelle")
    private String autoriteContractanteLibelle;

    @Column(name = "autorite_contractante_initiale")
    private String autoriteContractanteInitiale;

    @Column(name = "autorite_contractante_responsable")
    private String autoriteContractanteResponsable;

    @Column(name = "autorite_contractante_adress_mail")
    private String autoriteContractanteAdressMail;

    @Column(name = "autorite_contractante_site_web")
    private String autoriteContractanteSiteWeb;

    @Column(name = "autorite_contractante_adresse")
    private String autoriteContractanteAdresse;

    @Column(name = "autorite_contractante_telephone")
    private String autoriteContractanteTelephone;

    @Column(name = "autorite_contractante_fax")
    private String autoriteContractanteFax;

    @Column(name = "autorite_contractante_description")
    private String autoriteContractanteDescription;

    // jhipster-needle-entity-add-field - JHipster will add fields here

    public Long getId() {
        return this.id;
    }

    public AutoriteContractante id(Long id) {
        this.setId(id);
        return this;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAutoriteContractanteLibelle() {
        return this.autoriteContractanteLibelle;
    }

    public AutoriteContractante autoriteContractanteLibelle(String autoriteContractanteLibelle) {
        this.setAutoriteContractanteLibelle(autoriteContractanteLibelle);
        return this;
    }

    public void setAutoriteContractanteLibelle(String autoriteContractanteLibelle) {
        this.autoriteContractanteLibelle = autoriteContractanteLibelle;
    }

    public String getAutoriteContractanteInitiale() {
        return this.autoriteContractanteInitiale;
    }

    public AutoriteContractante autoriteContractanteInitiale(String autoriteContractanteInitiale) {
        this.setAutoriteContractanteInitiale(autoriteContractanteInitiale);
        return this;
    }

    public void setAutoriteContractanteInitiale(String autoriteContractanteInitiale) {
        this.autoriteContractanteInitiale = autoriteContractanteInitiale;
    }

    public String getAutoriteContractanteResponsable() {
        return this.autoriteContractanteResponsable;
    }

    public AutoriteContractante autoriteContractanteResponsable(String autoriteContractanteResponsable) {
        this.setAutoriteContractanteResponsable(autoriteContractanteResponsable);
        return this;
    }

    public void setAutoriteContractanteResponsable(String autoriteContractanteResponsable) {
        this.autoriteContractanteResponsable = autoriteContractanteResponsable;
    }

    public String getAutoriteContractanteAdressMail() {
        return this.autoriteContractanteAdressMail;
    }

    public AutoriteContractante autoriteContractanteAdressMail(String autoriteContractanteAdressMail) {
        this.setAutoriteContractanteAdressMail(autoriteContractanteAdressMail);
        return this;
    }

    public void setAutoriteContractanteAdressMail(String autoriteContractanteAdressMail) {
        this.autoriteContractanteAdressMail = autoriteContractanteAdressMail;
    }

    public String getAutoriteContractanteSiteWeb() {
        return this.autoriteContractanteSiteWeb;
    }

    public AutoriteContractante autoriteContractanteSiteWeb(String autoriteContractanteSiteWeb) {
        this.setAutoriteContractanteSiteWeb(autoriteContractanteSiteWeb);
        return this;
    }

    public void setAutoriteContractanteSiteWeb(String autoriteContractanteSiteWeb) {
        this.autoriteContractanteSiteWeb = autoriteContractanteSiteWeb;
    }

    public String getAutoriteContractanteAdresse() {
        return this.autoriteContractanteAdresse;
    }

    public AutoriteContractante autoriteContractanteAdresse(String autoriteContractanteAdresse) {
        this.setAutoriteContractanteAdresse(autoriteContractanteAdresse);
        return this;
    }

    public void setAutoriteContractanteAdresse(String autoriteContractanteAdresse) {
        this.autoriteContractanteAdresse = autoriteContractanteAdresse;
    }

    public String getAutoriteContractanteTelephone() {
        return this.autoriteContractanteTelephone;
    }

    public AutoriteContractante autoriteContractanteTelephone(String autoriteContractanteTelephone) {
        this.setAutoriteContractanteTelephone(autoriteContractanteTelephone);
        return this;
    }

    public void setAutoriteContractanteTelephone(String autoriteContractanteTelephone) {
        this.autoriteContractanteTelephone = autoriteContractanteTelephone;
    }

    public String getAutoriteContractanteFax() {
        return this.autoriteContractanteFax;
    }

    public AutoriteContractante autoriteContractanteFax(String autoriteContractanteFax) {
        this.setAutoriteContractanteFax(autoriteContractanteFax);
        return this;
    }

    public void setAutoriteContractanteFax(String autoriteContractanteFax) {
        this.autoriteContractanteFax = autoriteContractanteFax;
    }

    public String getAutoriteContractanteDescription() {
        return this.autoriteContractanteDescription;
    }

    public AutoriteContractante autoriteContractanteDescription(String autoriteContractanteDescription) {
        this.setAutoriteContractanteDescription(autoriteContractanteDescription);
        return this;
    }

    public void setAutoriteContractanteDescription(String autoriteContractanteDescription) {
        this.autoriteContractanteDescription = autoriteContractanteDescription;
    }

    // jhipster-needle-entity-add-getters-setters - JHipster will add getters and setters here

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AutoriteContractante)) {
            return false;
        }
        return id != null && id.equals(((AutoriteContractante) o).id);
    }

    @Override
    public int hashCode() {
        // see https://vladmihalcea.com/how-to-implement-equals-and-hashcode-using-the-jpa-entity-identifier/
        return getClass().hashCode();
    }

    // prettier-ignore
    @Override
    public String toString() {
        return "AutoriteContractante{" +
            "id=" + getId() +
            ", autoriteContractanteLibelle='" + getAutoriteContractanteLibelle() + "'" +
            ", autoriteContractanteInitiale='" + getAutoriteContractanteInitiale() + "'" +
            ", autoriteContractanteResponsable='" + getAutoriteContractanteResponsable() + "'" +
            ", autoriteContractanteAdressMail='" + getAutoriteContractanteAdressMail() + "'" +
            ", autoriteContractanteSiteWeb='" + getAutoriteContractanteSiteWeb() + "'" +
            ", autoriteContractanteAdresse='" + getAutoriteContractanteAdresse() + "'" +
            ", autoriteContractanteTelephone='" + getAutoriteContractanteTelephone() + "'" +
            ", autoriteContractanteFax='" + getAutoriteContractanteFax() + "'" +
            ", autoriteContractanteDescription='" + getAutoriteContractanteDescription() + "'" +
            "}";
    }
}
