package com.xtensus.passosyf.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    /* @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*").allowedMethods("*");
    }*/
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        corsRegistry
            .addMapping("/**")
            .allowedOrigins("*")
            .allowedMethods("*")
            .maxAge(3600L)
            .allowedHeaders("*")
            .exposedHeaders("Authorization");
    }

    // .allowCredentials(true)

    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
