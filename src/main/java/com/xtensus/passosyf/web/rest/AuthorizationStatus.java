package com.xtensus.passosyf.web.rest;

import org.springframework.stereotype.Component;

@Component
public class AuthorizationStatus {

    private boolean authorityStatus;

    public boolean getAuthorityStatus() {
        return authorityStatus;
    }

    public void setAuthorityStatus(boolean status) {
        this.authorityStatus = status;
    }
}
