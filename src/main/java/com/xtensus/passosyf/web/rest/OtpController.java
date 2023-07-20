package com.xtensus.passosyf.web.rest;

import java.util.HashMap;
import java.util.Map;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("api/otp")
public class OtpController {

    private final RestTemplate restTemplate;

    @Autowired
    public OtpController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostMapping("/users/{userId}/otp")
    public ResponseEntity<String> enableOtp(@PathVariable String userId, @RequestParam boolean enable) throws Exception {
        // Get an access token to authenticate with the Keycloak Admin REST API
        String accessToken = getAccessToken();

        // Construct the URL to enable/disable OTP for the user
        String enableOtpUrl = "http://localhost:8080/auth/admin/realms/google/users/" + userId + "/credential/otp";

        // Construct the request to enable/disable OTP for the user
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        String requestBody = "{\"enabled\":" + enable + "}";
        HttpEntity<String> request = new HttpEntity<>(requestBody, headers);

        // Send the request to enable/disable OTP for the user
        restTemplate.put(enableOtpUrl, request);

        if (enable) {
            return ResponseEntity.ok("OTP enabled for user with ID " + userId);
        } else {
            return ResponseEntity.ok("OTP disabled for user with ID " + userId);
        }
    }

    @GetMapping("/token")
    private String getAccessToken() throws Exception {
        // String tokenUrl = "http://localhost:9080/auth" + "/realms/" + "google" + "/protocol/openid-connect/token";
        String tokenUrl = "http://localhost:9080/auth/realms/google/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", "youtube");
        body.add("client_secret", "");
        body.add("username", "admin");
        body.add("password", "password");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        Map<String, Object> responseBody = response.getBody();
        // Extract the access token from the response body and return it
        if (responseBody != null && responseBody.containsKey("access_token")) {
            return responseBody.get("access_token").toString();
        } else {
            throw new Exception("Failed to get access token");
        }
    }
}
/* private final String keycloakUrl;
    private  final String realm;
    private  final String clientId;
    private  final String clientSecret;
    private  String adminUsername;
    private  String adminPassword;
    
    public void setUsername(String adminUsername) {
        this.adminUsername = adminUsername;
    }

    public void setPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    
    public OtpController(@Value("${keycloak.auth-server-url}") String keycloakUrl,
                           @Value("${keycloak.realm}") String realm,
                           @Value("${keycloak.resource}") String clientId,
                           @Value("${keycloak.credentials.secret}") String clientSecret) {
        
        this.keycloakUrl = keycloakUrl;
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        setUsername("admin");
        setPassword("admin");
    }
    
    @PostMapping("/{userId}/enable-otp")
    public ResponseEntity<Void> enableOtp(@PathVariable String userId) throws Exception {

            String accessToken = getAccessToken();
            String enableOtpUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/execute-actions-email";
            String body = "[\"CONFIGURE_OTP\"]";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(accessToken);
            
            HttpEntity<String> request = new HttpEntity<>(body, headers);
            
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.exchange(enableOtpUrl, HttpMethod.PUT, request, String.class);
            
            return ResponseEntity.ok().build();
        } 
    
    
    @PostMapping("/{userId}/disable-otp")
    public ResponseEntity<Void> disableOtp(@PathVariable String userId) throws Exception {

            String accessToken = getAccessToken();
            String disableOtpUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(accessToken);
            
            Map<String, Boolean> otpSettings = new HashMap<>();
            otpSettings.put("otpEnabled", false);
            otpSettings.put("otpPolicyType", null);
            otpSettings.put("otpConfigured", false);
            
            HttpEntity<Map<String, Boolean>> request = new HttpEntity<>(otpSettings, headers);
            
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.exchange(disableOtpUrl, HttpMethod.PUT, request, String.class);
            
            return ResponseEntity.ok().build();
        
    }
    
    private String getAccessToken() throws Exception {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("username", adminUsername);
        body.add("password", adminPassword);
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        Map<String, Object> responseBody = response.getBody();
// Extract the access token from the response body and return it
if (responseBody != null && responseBody.containsKey("access_token")) {
return responseBody.get("access_token").toString();
} else {
throw new Exception("Failed to get access token");
}
}
}*/
