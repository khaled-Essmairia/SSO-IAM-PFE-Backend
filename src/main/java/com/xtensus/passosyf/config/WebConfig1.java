package com.xtensus.passosyf.config;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.activation.DataSource;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.web.bind.annotation.PathVariable;
/*
@SuppressWarnings("deprecation")
@Configuration
@EnableWebMvcSecurity

public class WebConfig1 extends WebSecurityConfigurerAdapter   {
	


	 @Override
	 protected void configure(HttpSecurity http) throws Exception {

	   http.authorizeRequests()
	  .antMatchers("/user/functions**").access("hasRole('ROLE_ADMIN')")  
	  .antMatchers("/list**").access("hasRole('ROLE_USER')")
	  .anyRequest().permitAll()
	  .and()

	    .csrf();
	 }
	 
}*/
