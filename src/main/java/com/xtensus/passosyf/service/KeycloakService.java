package com.xtensus.passosyf.service;

import com.xtensus.passosyf.service.dto.KeycloakUserDTO;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import javax.ws.rs.core.Response;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessToken.Access;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class KeycloakService {

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    private Keycloak keycloak;

    @Autowired
    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    //List of users
    public List<UserRepresentation> getUsers111() {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();
        List<UserRepresentation> users = usersResource.list();
        return users;
    }

    //Get a single user by ID:
    public UserRepresentation getUserById(String userId) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();
        UserResource userResource = usersResource.get(userId);
        System.out.println(userId + "???????????????????");
        return userResource.toRepresentation();
    }

    //Create a new user:
    public UserRepresentation createUser1(UserRepresentation user) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();
        Response response = usersResource.create(user);
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        return getUserById(userId);
    }

    //Update an existing user:
    public void updateUser(String userId, UserRepresentation user) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();
        UserResource userResource = usersResource.get(userId);
        userResource.update(user);
    }

    //delete User
    public ResponseEntity<String> deleteUser(String userId) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();
        UserResource userResource = usersResource.get(userId);
        userResource.remove();
        return ResponseEntity.ok("User deleted successfully");
    }

    //search users
    public List<UserRepresentation> searchUsers(String search, Integer firstResult, Integer maxResults) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();
        List<UserRepresentation> users = new ArrayList<>();
        if (search != null) {
            List<UserRepresentation> searchResults = usersResource.search(search, firstResult, maxResults);
            users = searchResults.stream().map(this::mapUserRepresentation).collect(Collectors.toList());
        }
        return users;
    }

    //The UserRepresentation class does not have a constructor that takes a UserRepresentation argument, which is causing the first error.To fix this, you can create a static method in your service class that maps a UserRepresentation object to a new UserRepresentation object:
    private UserRepresentation mapUserRepresentation(UserRepresentation user) {
        UserRepresentation newUser = new UserRepresentation();
        newUser.setId(user.getId());
        newUser.setUsername(user.getUsername());
        newUser.setEmail(user.getEmail());
        newUser.setFirstName(user.getFirstName());
        newUser.setLastName(user.getLastName());
        newUser.setEnabled(user.isEnabled());
        newUser.setCredentials(user.getCredentials());
        newUser.setAttributes(user.getAttributes());
        newUser.setGroups(user.getGroups());
        newUser.setFederatedIdentities(user.getFederatedIdentities());
        return newUser;
    }

    /*
     public List<UserRepresentation> searchUsers(String search, Integer firstResult, Integer maxResults) {
    RealmResource realmResource = keycloak.realm(realm);
    UsersResource usersResource = realmResource.users();
    List<UserRepresentation> users = usersResource.search(search, firstResult, maxResults)
            .stream()
            .map(user -> {
                UserRepresentation userRep = new UserRepresentation();
                userRep.setId(user.getId());
                userRep.setCreatedTimestamp(user.getCreatedTimestamp());
                userRep.setEmail(user.getEmail());
                userRep.setEmailVerified(user.isEmailVerified());
                userRep.setEnabled(user.isEnabled());
                userRep.setFirstName(user.getFirstName());
                userRep.setLastName(user.getLastName());
                userRep.setUsername(user.getUsername());
                userRep.setAttributes(user.getAttributes());
                userRep.setGroups(user.getGroups());
                userRep.setFederatedIdentities(user.getFederatedIdentities());
                userRep.setRealmRoles(user.getRealmRoles());
                return userRep;
            })
            .collect(Collectors.toList());
    return users;
}

     */

    //create user
    public String createUser(UserRepresentation user, String password, String group, String role) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();

        System.out.println("user.getFirstName() " + user.getFirstName());
        // Set password if provided
        if (password != null && !password.isEmpty()) {
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(password);
            credential.setTemporary(false);
            user.setCredentials(Collections.singletonList(credential));
        }

        // Set group if provided
        if (group != null && !group.isEmpty()) {
            GroupRepresentation groupRepresentation = realmResource.groups().group(group).toRepresentation();
            List<String> groupIds = new ArrayList<>();
            groupIds.add(groupRepresentation.getId());
            user.setGroups(groupIds);
        }

        // Set role if provided
        if (role != null && !role.isEmpty()) {
            RoleRepresentation roleRepresentation = realmResource.roles().get(role).toRepresentation();
            user.setRealmRoles(Collections.singletonList(roleRepresentation.getName()));
        }

        Response response = usersResource.create(user);
        if (response.getStatus() != Response.Status.CREATED.getStatusCode()) {
            throw new RuntimeException("Failed to create user");
        }
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        return userId;
    }

    //get role by username
    public List<String> getUserRoles(String username) {
        List<String> roles = new ArrayList<>();
        RealmResource realm = keycloak.realm("google");
        UsersResource users = realm.users();
        List<UserRepresentation> userRepresentations = users.search(username, 0, 1);
        if (userRepresentations.size() == 1) {
            UserResource user = users.get(userRepresentations.get(0).getId());
            List<RoleRepresentation> roleRepresentations = user.roles().realmLevel().listEffective();
            for (RoleRepresentation role : roleRepresentations) {
                roles.add(role.getName());
            }
        }
        return roles;
    }

    //remove user from group
    public void removeUserFromGroup(String groupName, String username) {
        GroupRepresentation group = keycloak.realm(realm).groups().group(groupName).toRepresentation();
        UserRepresentation user = keycloak.realm(realm).users().search(username).get(0);
        keycloak.realm(realm).users().get(user.getId()).leaveGroup(group.getId());
    }

    //remove role from group
    public void removeRoleFromGroup(String groupName, String roleName) {
        GroupRepresentation group = keycloak.realm(realm).groups().group(groupName).toRepresentation();
        RoleRepresentation role = keycloak.realm(realm).roles().get(roleName).toRepresentation();
        keycloak.realm(realm).groups().group(group.getId()).roles().realmLevel().remove(Arrays.asList(role));
    }

    //remove role from user
    public void removeRoleFromUser(String username, String roleName) {
        UserRepresentation user = keycloak.realm(realm).users().search(username).get(0);
        RoleRepresentation role = keycloak.realm(realm).roles().get(roleName).toRepresentation();
        keycloak.realm(realm).users().get(user.getId()).roles().realmLevel().remove(Arrays.asList(role));
    }

    //add role to user
    public void addRoleToUser(String username, String roleName) {
        UserRepresentation user = keycloak.realm(realm).users().search(username).get(0);
        RoleRepresentation role = keycloak.realm(realm).roles().get(roleName).toRepresentation();
        keycloak.realm(realm).users().get(user.getId()).roles().realmLevel().add(Arrays.asList(role));
    }

    //get group members
    public List<String> getGroupMembers(String groupName) {
        // get the Keycloak realm
        RealmResource realmResource = keycloak.realm(realm);

        // get the Keycloak Group object using the group name
        GroupRepresentation group = realmResource.groups().group(groupName).toRepresentation();

        // get the list of member IDs for the group
        List<String> memberIds = realmResource
            .groups()
            .group(group.getId())
            .members()
            .stream()
            .map(UserRepresentation::getId)
            .collect(Collectors.toList());

        // get the list of member usernames for the group
        List<String> memberUsernames = memberIds
            .stream()
            .map(userId -> realmResource.users().get(userId).toRepresentation())
            .map(UserRepresentation::getUsername)
            .collect(Collectors.toList());

        return memberUsernames;
    }

    //create group
    public void createGroup(String groupName) {
        RealmResource realmResource = keycloak.realm("google");
        GroupRepresentation group = new GroupRepresentation();
        group.setName(groupName);
        realmResource.groups().add(group);
    }

    //crzate role
    public void createRole(String roleName) {
        RealmResource realmResource = keycloak.realm("google");
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        role.setClientRole(false); // set to true if client role
        realmResource.roles().create(role);
    }

    //Add Role to Group Function
    public void addRoleToGroup(String roleName, String groupName) {
        RealmResource realmResource = keycloak.realm("google");
        RoleRepresentation role = realmResource.roles().get(roleName).toRepresentation();
        GroupRepresentation group = realmResource.groups().group(groupName).toRepresentation();
        group.getRealmRoles().add(role.getName());
        realmResource.groups().group(group.getId()).update(group);
    }

    //get role id
    public String getRoleId(String roleName) {
        RoleRepresentation role = keycloak.realm("your-realm-name").roles().get(roleName).toRepresentation();
        if (role != null) {
            return role.getId();
        } else {
            throw new RuntimeException("Role not found: " + roleName);
        }
    }

    //get group id
    public String getGroupId(String groupName) {
        GroupRepresentation group = keycloak.realm("your-realm-name").groups().group(groupName).toRepresentation();
        if (group != null) {
            return group.getId();
        } else {
            throw new RuntimeException("Group not found: " + groupName);
        }
    }
}
