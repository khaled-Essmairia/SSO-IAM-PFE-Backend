package com.xtensus.passosyf.web.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xtensus.passosyf.config.SecurityConfiguration;
//import org.keycloak.representations.idm.OTPPolicyRepresentation;
//import org.keycloak.admin.client.resource.AuthenticatorConfigResource;
import com.xtensus.passosyf.security.SecurityUtils;
import com.xtensus.passosyf.service.Group;
import com.xtensus.passosyf.service.KeycloakService;
import com.xtensus.passosyf.service.dto.AdminUserDTO;
import com.xtensus.passosyf.web.Authorize;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.Response;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.authentication.RequiredActionSpi;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.ServerConfiguration;
import org.keycloak.authorization.client.util.Throwables;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
//import org.keycloak.authorization.client.resource.PermissionResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserFederationMapperRepresentation;
import org.keycloak.representations.idm.UserFederationProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "*")
public class UserController {

    private KeycloakService keycloakUserService;
    private AuthorizationStatus authorizationStatus;

    @Autowired
    public UserController(KeycloakService keycloakUserService, AuthorizationStatus authorizationStatus) {
        this.keycloakUserService = keycloakUserService;
        this.authorizationStatus = authorizationStatus;
    }

     //@Authorize
    @GetMapping("users/liste-users")
    public List<UserRepresentation> getUser() {
        return keycloakUserService.getUsers111();
    }

    /*  @GetMapping("users/liste-users")
    public ResponseEntity<?> getUser() {
        Map<String, String> khaled = new HashMap<>();
        String desiredPath = "functions";
        String desiredPermission = "READ";
        String desiredRole = "ROLE_ADMIN";
        khaled.put("desiredPath", desiredPath);
        khaled.put("desiredPermission", desiredPermission);
        khaled.put("desiredRole", desiredRole);

        boolean hasAuthority = hasAuthority();

        if (hasAuthority) {
            // User has the required authority, proceed with retrieving the users
            List<UserRepresentation> users = keycloakUserService.getUsers111();
            return ResponseEntity.ok(users);
        } else {
            // User does not have the required authority
            System.out.println("User does not have the required authority.");
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonList("Access denied"));
        }
    }*/

    @GetMapping("users/{id}")
    public ResponseEntity<UserRepresentation> getUser(@PathVariable String id) {
        UserRepresentation user = keycloakUserService.getUserById(id);
        return ResponseEntity.ok(user);
    }

    //@Authorize
    @PutMapping("/users/{userId}")
    public void updateUser(@PathVariable String userId, @RequestBody UserRepresentation user) {
        System.out.println(user);
        keycloakUserService.updateUser(userId, user);
        System.out.println(user);
    }

    //not working with angular but works with postman and not works because miss of some attribute like credentials : password
    @PostMapping("/users1")
    public ResponseEntity<String> createUser00(
        @RequestBody UserRepresentation user,
        @RequestParam(required = false) String password,
        @RequestParam(required = false) String group,
        @RequestParam(required = false) String role
    ) {
        System.out.println("**********************************");

        System.out.println(user.toString());
        String userId = keycloakUserService.createUser(user, password, group, role);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(userId).toUri();
        return ResponseEntity.created(location).body(userId);
    }

    // @Authorize
    @PostMapping("/users/user")
    public ResponseEntity<UserRepresentation> createUser(@RequestBody UserRepresentation user) {
        UserRepresentation createdUser = keycloakUserService.createUser1(user);
        enableUser(createdUser.getId()); // Call to enableUser function
        return ResponseEntity.created(URI.create(createdUser.getId())).body(createdUser);
    }

    //  @Authorize
    @DeleteMapping("/users/{userId}")
    //@CrossOrigin(origins = "http://localhost:9000")
    public void deleteUser(@PathVariable String userId) {
        keycloakUserService.deleteUser(userId);
    }

    //out of service
    @GetMapping("/users/search")
    public List<UserRepresentation> searchUsers(
        @RequestParam(required = false) String search,
        @RequestParam(required = false) Integer firstResult,
        @RequestParam(required = false) Integer maxResults
    ) {
        System.out.println(keycloakUserService.searchUsers(search, firstResult, maxResults).size());
        return keycloakUserService.searchUsers(search, firstResult, maxResults);
    }

    @GetMapping("/users/{username}/roles")
    public ResponseEntity<List<String>> getUserRoles(@PathVariable String username) {
        List<String> roles = keycloakUserService.getUserRoles(username);
        System.out.println("******************");
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getAuthorities());
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/rolesName")
    //@Authorize
    public List<String> getRolesNames() {
        RealmResource realmResource = keycloak.realm("google");
        List<RoleRepresentation> roles = realmResource.roles().list();
        return roles.stream().map(RoleRepresentation::getName).collect(Collectors.toList());
    }

    @GetMapping("/rolesdetails")
    public List<RoleRepresentation> getRolesDetails() {
        RealmResource realmResource = keycloak.realm("google");
        List<RoleRepresentation> roles = realmResource.roles().list();
        return roles;
    }

    @Authorize
    @GetMapping("/rolesND")
    public List<Map<String, String>> getRolesNameDesc() {
        RealmResource realmResource = keycloak.realm("google");
        List<RoleRepresentation> roles = realmResource.roles().list();
        List<Map<String, String>> result = new ArrayList<>();
        for (RoleRepresentation role : roles) {
            Map<String, String> roleMap = new HashMap<>();
            roleMap.put("name", role.getName());
            roleMap.put("description", role.getDescription());
            result.add(roleMap);
        }
        return result;
    }

    @GetMapping("/groupsname")
    public List<String> getGroupsName() {
        RealmResource realmResource = keycloak.realm("google");
        List<GroupRepresentation> groups = realmResource.groups().groups();
        return groups.stream().map(GroupRepresentation::getName).collect(Collectors.toList());
    }

    @GetMapping("/groupsnamerepresentation")
    public List<GroupRepresentation> getGroupsNameRepresentation() {
        RealmResource realmResource = keycloak.realm("google");
        List<GroupRepresentation> groups = realmResource.groups().groups();
        return groups;
    }

    @Autowired
    private Keycloak keycloak;

    @PostMapping("/create-group")
    public ResponseEntity<String> createGroup(@RequestBody Map<String, String> groupData) {
        String groupName = groupData.get("groupName");
        String groupDescription = groupData.get("groupDescription");
        if (groupName == null || groupName.isEmpty()) {
            return ResponseEntity.badRequest().body("Group name must be provided");
        }
        try {
            GroupRepresentation newGroup = new GroupRepresentation();
            newGroup.setName(groupName);
            Map<String, List<String>> attributes = new HashMap<>();
            if (groupDescription != null && !groupDescription.isEmpty()) {
                attributes.put("description", Collections.singletonList(groupDescription));
            }
            newGroup.setAttributes(attributes);
            keycloak.realm("google").groups().add(newGroup);
            return ResponseEntity.ok("Group created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error creating group: " + e.getMessage());
        }
    }

    //get only attributes
    @GetMapping("/groups/{groupId}/attributes")
    public Map<String, List<String>> getGroupAttributes(@PathVariable String groupId) {
        // Get the group by ID
        GroupRepresentation group = keycloak.realm("google").groups().group(groupId).toRepresentation();
        // Get the attributes of the group
        Map<String, List<String>> attributes = group.getAttributes();
        return attributes;
    }

    @GetMapping("/groups/all")
    public List<Map<String, Object>> getAllGroupsWithAttributes() {
        // Get all groups in the realm
        List<GroupRepresentation> groups = keycloak.realm("google").groups().groups();

        // Create a list to store the attributes of each group
        List<Map<String, Object>> groupsWithAttributes = new ArrayList<>();

        // Iterate over the groups and retrieve their attributes
        for (GroupRepresentation group : groups) {
            // Get the group by ID
            GroupRepresentation groupRepresentation = keycloak.realm("google").groups().group(group.getId()).toRepresentation();

            // Create a map to store the group ID and attributes
            Map<String, Object> groupWithAttributes = new HashMap<>();
            groupWithAttributes.put("id", groupRepresentation.getId());
            groupWithAttributes.put("name", groupRepresentation.getName());
            //groupWithAttributes.put("attributes", groupRepresentation.getAttributes());
            // Retrieve the group's description attribute
            List<String> descriptionList = groupRepresentation.getAttributes().get("description");
            String description = descriptionList != null && !descriptionList.isEmpty() ? descriptionList.get(0) : "";
            groupWithAttributes.put("description", description);

            groupsWithAttributes.add(groupWithAttributes);
        }

        return groupsWithAttributes;
    }

    @GetMapping("/groupsId/{groupId}")
    public ResponseEntity<GroupRepresentation> getGroupById(@PathVariable String groupId) {
        try {
            GroupRepresentation groupRepresentation = keycloak.realm("google").groups().group(groupId).toRepresentation();
            return ResponseEntity.ok(groupRepresentation);
        } catch (javax.ws.rs.NotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PutMapping("/update-group/{groupId}")
    public ResponseEntity<String> updateGroup(@PathVariable("groupId") String groupId, @RequestBody Map<String, String> groupData) {
        if (groupId == null || groupId.isEmpty()) {
            return ResponseEntity.badRequest().body("Group ID must be provided");
        }

        try {
            GroupRepresentation group = keycloak.realm("google").groups().group(groupId).toRepresentation();

            if (group == null) {
                return ResponseEntity.notFound().build();
            }

            String groupName = groupData.get("groupName");
            if (groupName != null && !groupName.isEmpty()) {
                group.setName(groupName);
            }

            String groupDescription = groupData.get("groupDescription");
            if (groupDescription != null && !groupDescription.isEmpty()) {
                group.setAttributes(Collections.singletonMap("description", Arrays.asList(groupDescription)));
            }

            keycloak.realm("google").groups().group(groupId).update(group);
            return ResponseEntity.ok("Group updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error updating group: " + e.getMessage());
        }
    }

    @PostMapping("/create-role")
    public ResponseEntity<String> createRole(@RequestBody Map<String, String> roleData) {
        String roleName = roleData.get("roleName");
        if (roleName == null || roleName.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name must be provided");
        }
        try {
            RoleRepresentation newRole = new RoleRepresentation();
            newRole.setName(roleName);
            keycloak.realm("google").roles().create(newRole);
            return ResponseEntity.ok("Role created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error creating role: " + e.getMessage());
        }
    }

    @PostMapping("/add-role-to-user")
    public ResponseEntity<String> addRoleToUser(@RequestBody Map<String, String> roleData) {
        String roleName = roleData.get("roleName");
        String username = roleData.get("username");
        if (roleName == null || roleName.isEmpty() || username == null || username.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name and username must be provided");
        }
        try {
            RoleRepresentation role = keycloak.realm("google").roles().get(roleName).toRepresentation();
            UserRepresentation user = keycloak.realm("google").users().search(username).get(0);
            keycloak.realm("google").users().get(user.getId()).roles().realmLevel().add(Arrays.asList(role));
            return ResponseEntity.ok("Role added to user successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error adding role to user: " + e.getMessage());
        }
    }

    @DeleteMapping("/delete-role-from-user")
    public ResponseEntity<String> deleteRoleFromUser(@RequestBody Map<String, String> roleData) {
        String roleName = roleData.get("roleName");
        String username = roleData.get("username");
        if (roleName == null || roleName.isEmpty() || username == null || username.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name and username must be provided");
        }
        try {
            RoleRepresentation role = keycloak.realm("google").roles().get(roleName).toRepresentation();
            UserRepresentation user = keycloak.realm("google").users().search(username).get(0);
            keycloak.realm("google").users().get(user.getId()).roles().realmLevel().remove(Arrays.asList(role));
            return ResponseEntity.ok("Role removed from user successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error removing role from user: " + e.getMessage());
        }
    }

    @DeleteMapping("/delete-group")
    public ResponseEntity<String> deleteGroup(@RequestBody Map<String, String> groupData) {
        String groupName = groupData.get("groupName");
        if (groupName == null || groupName.isEmpty()) {
            return ResponseEntity.badRequest().body("Group name must be provided");
        }
        try {
            GroupRepresentation group = keycloak.realm("google").groups().groups(groupName, 0, 1).get(0);
            keycloak.realm("google").groups().group(group.getId()).remove();
            return ResponseEntity.ok("Group deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error deleting group: " + e.getMessage());
        }
    }

    @DeleteMapping("/delete-group/{groupId}")
    public ResponseEntity<String> deleteGroup(@PathVariable String groupId) {
        if (groupId == null || groupId.isEmpty()) {
            return ResponseEntity.badRequest().body("Group ID must be provided");
        }
        try {
            keycloak.realm("google").groups().group(groupId).remove();
            return ResponseEntity.ok("Group deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error deleting group: " + e.getMessage());
        }
    }

    @PostMapping("/search-user")
    public ResponseEntity<List<UserRepresentation>> searchUser(@RequestBody Map<String, String> userData) {
        String search = userData.get("search");
        if (search == null || search.isEmpty()) {
            return ResponseEntity.badRequest().body(Collections.emptyList());
        }
        try {
            List<UserRepresentation> users = keycloak.realm("google").users().search(search);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.emptyList());
        }
    }

    //new one
    
    @DeleteMapping("/delete-role")
    public ResponseEntity<String> deleteRoleByName(@RequestBody Map<String, String> roleData) {
        String roleName = roleData.get("roleName");
        Logger logger = LoggerFactory.getLogger(UserController.class);
        if (roleName == null || roleName.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name must be provided");
        }
        try {
            RoleResource roleResource = keycloak.realm("google").roles().get(roleName);
            if (roleResource == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error deleting role: role not found");
            }
            roleResource.remove();

            return ResponseEntity.ok("Role deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error deleting role: " + e.getMessage());
        }
    }

    @GetMapping("/role/{roleName}")
    public ResponseEntity<String> getRoleId(@PathVariable String roleName) {
        try {
            RoleRepresentation role = keycloak.realm("google").roles().get(roleName).toRepresentation();
            if (role != null) {
                String roleId = role.getId();
                return ResponseEntity.ok(roleId);
            } else {
                throw new RuntimeException("Role not found: " + roleName);
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error getting role ID: " + e.getMessage());
        }
    }

    @PostMapping("/users/{userId}/reset-password")
    public void addUserPassword(@PathVariable String userId, @RequestBody String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);

        keycloak.realm("google").users().get(userId).resetPassword(credential);
    }

    @PutMapping("/users/{userId}/disable")
    public void disableUser(@PathVariable String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation user = userResource.toRepresentation();
        user.setEnabled(false);
        userResource.update(user);
    }

    @PutMapping("/users/{userId}/enable")
    public void enableUser(@PathVariable String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation user = userResource.toRepresentation();
        user.setEnabled(true);
        userResource.update(user);
    }
    /*******************************************isEnabled********************************************/
    @GetMapping("/{userId}/isEnabled")
    public boolean isEnabled(@PathVariable String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation user = userResource.toRepresentation();
       return user.isEnabled();
    }
    
    @GetMapping("/{userId}/isOtpEnabled")
    public ResponseEntity<Boolean> isOtpEnabled(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
        boolean isOtpEnabled = requiredActions.contains("CONFIGURE_TOTP");
        return ResponseEntity.ok(isOtpEnabled);
    }


    @GetMapping("/groups/{groupId}/members")
    public List<UserRepresentation> getGroupMembers(@PathVariable String groupId) {
        // Get the GroupResource for the specified group ID
        GroupResource groupResource = keycloak.realm("google").groups().group(groupId);
        // Get the list of members in the group
        List<UserRepresentation> members = groupResource.members();
        // keycloak.close();
        return members;
    }

    @GetMapping("/groups/{groupId}/membersUsernames")
    public List<String> getGroupMemberUsernames(@PathVariable String groupId) {
        // Get the GroupResource for the specified group ID
        GroupResource groupResource = keycloak.realm("google").groups().group(groupId);
        // Get the list of members in the group
        List<UserRepresentation> members = groupResource.members();
        // Extract the usernames from the UserRepresentation objects
        List<String> usernames = members.stream().map(UserRepresentation::getUsername).collect(Collectors.toList());
        // Close the Keycloak connection
        // keycloak.close();
        return usernames;
    }

    /*//////////////////////////////////////////////////////////////////////////*/
    @PostMapping("/users/{userId}/groups/{groupId}")
    public Response addUserToGroup1(@PathVariable String userId, @PathVariable String groupId) {
        try {
            // Get the user resource
            UsersResource usersResource = keycloak.realm("google").users();
            UserResource userResource = usersResource.get(userId);
            System.out.println("user name is************************ " + userResource.toRepresentation().getFirstName());
            // Get the group resource
            GroupResource groupResource = keycloak.realm("google").groups().group(groupId);
            System.out.println("group name is************************ " + groupResource.toRepresentation().getName());
            // Check if the user is already a member of the group
            List<GroupRepresentation> groups = userResource.groups();
            for (GroupRepresentation group : groups) {
                if (group.getId().equals(groupId)) {
                    return Response.status(Response.Status.OK).entity("User is already a member of the group.").build();
                }
            }
            // Add the user to the group
            // groupResource.members().add(userResource.toRepresentation());
            keycloak.realm("google").users().get(userId).joinGroup(groupId);
            System.out.println(groupResource + "group*********************************");
            System.out.println(userResource + "user***********************************");
            return Response.status(Response.Status.OK).entity("User has been added to the group.").build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }
    }

    /**^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^**/
    @DeleteMapping("/roles/{roleId}")
    public ResponseEntity<String> deleteRoleById(@PathVariable String roleId) {
        RolesResource rolesResource = keycloak.realm("google").roles();
        //RoleRepresentation role = rolesResource.get(roleId).toRepresentation();
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        ResponseEntity<RoleRepresentation> rol = getRoleById(roleId);
        String roleName = rol.getBody().getName();
        ResponseEntity<String> del = deleteRoleByName(Collections.singletonMap("roleName", roleName));
        return ResponseEntity.ok("Role deleted successfully");
    }

    @PutMapping("/update-role/{idRole}")
    public ResponseEntity<String> updateRole(@PathVariable("idRole") String idRole, @RequestBody Map<String, String> roleData) {
        if (idRole == null || idRole.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name must be provided");
        }

        ResponseEntity<RoleRepresentation> rol = getRoleById(idRole);
        String roleName = rol.getBody().getName();

        RoleResource role1 = keycloak.realm("google").roles().get(roleName);
        RoleRepresentation role = role1.toRepresentation();

        if (role == null) {
            return ResponseEntity.notFound().build();
        }

        String newRoleName = roleData.get("name");
        if (newRoleName != null && !newRoleName.isEmpty()) {
            role.setName(newRoleName);
        }

        String roleDescription = roleData.get("description");
        if (roleDescription != null && !roleDescription.isEmpty()) {
            role.setDescription(roleDescription);
        }

        keycloak.realm("google").roles().get(roleName).update(role);
        return ResponseEntity.ok("Role updated successfully");
    }

    @GetMapping("/groups/{groupId}/users/not-in-group")
    /* public List<UserRepresentation> getUsersNotInGroup(@PathVariable String groupId) {
        RealmResource realmResource = keycloak.realm("google");
        GroupRepresentation group = realmResource.groups().group(groupId).toRepresentation();
        List<UserRepresentation> allUsers = realmResource.users().list().stream().map(UserRepresentation.class::cast).collect(Collectors.toList());
        List<UserRepresentation> usersInGroup = realmResource.groups().group(groupId).members().stream().map(UserRepresentation.class::cast).collect(Collectors.toList());
        allUsers.removeAll(usersInGroup);
        return allUsers;}*/
    /* public List<UserRepresentation> getUsersNotInGroup(@RequestParam String groupId) {
        List<UserRepresentation> allUsers = keycloak.users().list().getUsers();
        List<UserRepresentation> groupUsers = keycloak.users().list().search("", 0, 1000, groupId).getUsers();
        List<UserRepresentation> usersNotInGroup = new ArrayList<>(allUsers);
        usersNotInGroup.removeAll(groupUsers);
        return usersNotInGroup;    }*/
    public List<UserRepresentation> getUsersNotInGroup(@PathVariable String groupId) {
        Logger logger = LoggerFactory.getLogger(KeycloakService.class);

        List<UserRepresentation> allUsers = keycloak.realm("google").users().list();
        List<UserRepresentation> usersInGroup = keycloak.realm("google").groups().group(groupId).members();
        List<UserRepresentation> usersNotInGroup = new ArrayList<>();

        for (UserRepresentation user : allUsers) {
            logger.info(" allusername:*************** " + user.getUsername());
        }

        for (UserRepresentation user : usersInGroup) {
            logger.info(" usernameInGroup: ***************" + user.getUsername());
        }

        /* for (UserRepresentation user : allUsers) {
            if (!usersInGroup.contains(user)) {
                usersNotInGroup.add(user);
            }
        }*/
        for (UserRepresentation user : allUsers) {
            boolean userInGroup = false;
            for (UserRepresentation groupUser : usersInGroup) {
                if (groupUser.getId().equals(user.getId())) {
                    userInGroup = true;
                    break;
                }
            }
            if (!userInGroup) {
                usersNotInGroup.add(user);
            }
        }
        for (UserRepresentation user : usersNotInGroup) {
            logger.info(" usernameNotInGroup: *****************" + user.getUsername());
        }
        return usersNotInGroup;
    }

    @GetMapping("/groupsuser/{userId}")
    public List<GroupRepresentation> getUserGroups(@PathVariable String userId) {
        List<GroupRepresentation> userGroups = new ArrayList<>();
        List<GroupRepresentation> groupIds = keycloak.realm("google").users().get(userId).groups();
        List<String> userGroupIds = new ArrayList<>();
        for (GroupRepresentation group : groupIds) {
            userGroupIds.add(group.getId());
        }
        for (String groupId : userGroupIds) {
            GroupRepresentation group = keycloak.realm("google").groups().group(groupId).toRepresentation();
            group.setId(groupId); // set the id of the group
            userGroups.add(group);
        }
        return userGroups;
    }

    @GetMapping("/groups/notassigned/{userId}")
    public List<Group> getGroupsNotAssignedToUser(@PathVariable String userId) {
        List<Group> groupsNotAssigned = new ArrayList<>();
        List<GroupRepresentation> allGroups = keycloak.realm("google").groups().groups();
        List<GroupRepresentation> userGroups = keycloak.realm("google").users().get(userId).groups();
        for (GroupRepresentation groupRep : allGroups) {
            if (!userGroups.stream().anyMatch(g -> g.getId().equals(groupRep.getId()))) {
                Group group = new Group(groupRep.getId(), groupRep.getName());
                groupsNotAssigned.add(group);
            }
        }
        return groupsNotAssigned;
    }

    //out of service because return only one group
    // @GetMapping("/groupsuser/{userId}")
    public List<Group> getUserGroups1(@PathVariable String userId) {
        List<Group> userGroups = new ArrayList<>();
        List<GroupRepresentation> groupReps = keycloak.realm("google").users().get(userId).groups();
        List<String> groupIds = new ArrayList<>();
        for (GroupRepresentation groupRep : groupReps) {
            groupIds.add(groupRep.getId());
        }
        for (String groupId : groupIds) {
            GroupRepresentation groupRep = keycloak.realm("google").groups().group(groupId).toRepresentation();
            Group group = new Group();
            group.setId(groupId);
            group.setName(groupRep.getName());
            // group.setDesc(groupRep.getAttributes().get("description").get(0));
            userGroups.add(group);
        }
        return userGroups;
    }

    @GetMapping("/groupRole/{groupId}/Assigned")
    public List<RoleRepresentation> showRolesForGroup(@PathVariable String groupId) {
        GroupResource groupResource = keycloak.realm("google").groups().group(groupId);
        RolesResource rolesResource = keycloak.realm("google").roles();
        // Get the RoleScopeResource for the group
        RoleScopeResource roleScopeResource = groupResource.roles().realmLevel();
        // Get a list of all roles assigned to the group
        List<RoleRepresentation> assignedRoles = roleScopeResource.listAll();
        // Print the names of the assigned roles
        // System.out.println("Roles assigned to group " + groupId + ":");
        for (RoleRepresentation role : assignedRoles) {
            System.out.println("- " + role.getName());
        }
        return assignedRoles;
    }

    @GetMapping("/groupRole/{groupId}/notAssigned")
    public List<RoleRepresentation> showRolesNotAssignedToGroup(@PathVariable String groupId) {
        GroupResource groupResource = keycloak.realm("google").groups().group(groupId);
        RolesResource rolesResource = keycloak.realm("google").roles();
        // Get the RoleScopeResource for the group
        RoleScopeResource roleScopeResource = groupResource.roles().realmLevel();
        // Get a list of all roles assigned to the group
        List<RoleRepresentation> assignedRoles = roleScopeResource.listAll();
        // Get a list of all roles in the realm
        List<RoleRepresentation> allRoles = rolesResource.list();
        // Get the difference between all roles and assigned roles
        allRoles.removeAll(assignedRoles);
        // Print the names of the unassigned roles
        System.out.println("Roles not assigned to group " + groupId + ":");
        for (RoleRepresentation role : allRoles) {
            System.out.println("- " + role.getName());
        }
        return allRoles;
    }

    @DeleteMapping("/delete-user-from-group")
    public ResponseEntity<String> deleteUserFromGroup(@RequestBody Map<String, String> userData) {
        String username = userData.get("username");
        String groupName = userData.get("groupName");
        if (username == null || username.isEmpty() || groupName == null || groupName.isEmpty()) {
            return ResponseEntity.badRequest().body("Username and group name must be provided");
        }
        try {
            UserRepresentation user = keycloak.realm("google").users().search(username, 0, 1).get(0);
            List<GroupRepresentation> groups = keycloak.realm("google").users().get(user.getId()).groups();
            for (GroupRepresentation group : groups) {
                if (group.getName().equals(groupName)) {
                    keycloak.realm("google").users().get(user.getId()).leaveGroup(group.getId());
                }
            }
            return ResponseEntity.ok("User deleted from group successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error deleting user from group: " + e.getMessage());
        }
    }

    @DeleteMapping("/delete-role-from-group")
    public ResponseEntity<String> deleteRoleFromGroup(@RequestBody Map<String, String> roleData) {
        String roleName = roleData.get("roleName");
        String groupName = roleData.get("groupName");
        if (roleName == null || roleName.isEmpty() || groupName == null || groupName.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name and group name must be provided");
        }
        try {
            RoleRepresentation role = keycloak.realm("google").roles().get(roleName).toRepresentation();
            GroupRepresentation group = keycloak.realm("google").groups().groups(groupName, 0, 1).get(0);
            keycloak.realm("google").groups().group(group.getId()).roles().realmLevel().remove(Arrays.asList(role));
            return ResponseEntity.ok("Role removed from group successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error removing role from group: " + e.getMessage());
        }
    }

    @PostMapping("/add-role-to-group")
    public ResponseEntity<String> addRoleToGroup(@RequestBody Map<String, String> roleData) {
        String roleName = roleData.get("roleName");
        String groupName = roleData.get("groupName");
        if (roleName == null || roleName.isEmpty() || groupName == null || groupName.isEmpty()) {
            return ResponseEntity.badRequest().body("Role name and group name must be provided");
        }
        try {
            RoleRepresentation role = keycloak.realm("google").roles().get(roleName).toRepresentation();
            GroupRepresentation group = keycloak.realm("google").groups().groups(groupName, 0, 1).get(0);
            keycloak.realm("google").groups().group(group.getId()).roles().realmLevel().add(Collections.singletonList(role));
            return ResponseEntity.ok("Role added to group successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error adding role to group: " + e.getMessage());
        }
    }

    /*----------------------------------------------------*/
    @GetMapping("/roles/{roleId}")
    public ResponseEntity<RoleRepresentation> getRoleById(@PathVariable String roleId) {
        try {
            //RoleResource roleResource = keycloak.realm("google").rolesById().get(roleId);
            RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
            if (role != null) {
                return ResponseEntity.ok(role);
            } else {
                System.out.println("Role not found");
                return ResponseEntity.notFound().build();
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
    /**********************************************OTP + User required Actions****************************************************/

    // requiredActions.add("update_user_locale");
    // requiredActions.add("CONFIGURE_TOTP");
    // requiredActions.add("VERIFY_EMAIL");
    // requiredActions.add("UPDATE_PASSWORD");
   //  requiredActions.add("UPDATE_PROFILE");
    @GetMapping("/{userId}/updateProfile")
    public ResponseEntity<List<String>> updateProfile(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
        // Add "update_profile" to the required actions list if not already present
       if (!requiredActions.contains("UPDATE_PROFILE")) {
            requiredActions.add("UPDATE_PROFILE");
        }
        userRepresentation.setRequiredActions(requiredActions);
        userResource.update(userRepresentation);
        return ResponseEntity.ok(requiredActions);
    }
    @GetMapping("/{userId}/disableUpdateProfile")
    public ResponseEntity<List<String>> disableUpdateProfile(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
        // Remove "update_profile" from the required actions list if present
        if (requiredActions.contains("UPDATE_PROFILE")) {
            requiredActions.remove("UPDATE_PROFILE");
        }
        userRepresentation.setRequiredActions(requiredActions);
        userResource.update(userRepresentation);
        
        return ResponseEntity.ok(requiredActions);
    }

    @GetMapping("/{userId}/updatePassword")
    public ResponseEntity<List<String>> updatePassword(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
        // Add "update_profile" to the required actions list if not already present
       if (!requiredActions.contains("UPDATE_PASSWORD")) {
            requiredActions.add("UPDATE_PASSWORD");
        }
        userRepresentation.setRequiredActions(requiredActions);
        userResource.update(userRepresentation);
        return ResponseEntity.ok(requiredActions);
    }
    
    @GetMapping("/{userId}/disableUpdatePassword")
    public ResponseEntity<List<String>> disableUpdatePassword(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
       if (requiredActions.contains("UPDATE_PASSWORD")) {
            requiredActions.remove("UPDATE_PASSWORD");
        }
        userRepresentation.setRequiredActions(requiredActions);
        userResource.update(userRepresentation);
        return ResponseEntity.ok(requiredActions);
    }
    
    
    @GetMapping("/{userId}/enableOtp")
    public ResponseEntity<List<String>> enableOtp(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
        // Add "update_profile" to the required actions list if not already present
       if (!requiredActions.contains("CONFIGURE_TOTP")) {
            requiredActions.add("CONFIGURE_TOTP");
        }
        userRepresentation.setRequiredActions(requiredActions);
        userResource.update(userRepresentation);
        return ResponseEntity.ok(requiredActions);
    }
    
    @GetMapping("/{userId}/disableOtp")
    public ResponseEntity<List<String>> disableOtp(@PathVariable("userId") String userId) {
        UserResource userResource = keycloak.realm("google").users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        List<String> requiredActions = userRepresentation.getRequiredActions();
        // Add "update_profile" to the required actions list if not already present
       if (requiredActions.contains("CONFIGURE_TOTP")) {
            requiredActions.remove("CONFIGURE_TOTP");
        }
        userRepresentation.setRequiredActions(requiredActions);
        userResource.update(userRepresentation);
        return ResponseEntity.ok(requiredActions);
    }




    /********************************************restriction des roles**********************************************************/

    protected ClientResource getClient() {
        return getClient(getRealm());
    }

    protected ClientResource getClient(RealmResource realm) {
        ClientsResource clients = realm.clients();
        return clients
            .findByClientId("backend")
            .stream()
            .map(representation -> clients.get(representation.getId()))
            .findFirst()
            .orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }

    protected RealmResource getRealm() {
        try {
            return keycloak.realm("google");
        } catch (Exception cause) {
            throw new RuntimeException("Failed to create admin client", cause);
        }
    }

    @PostMapping("/ressource")
    private void createResourcesAndScopes() throws IOException {
        Set<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("read"));
        scopes.add(new ScopeRepresentation("write"));
        scopes.add(new ScopeRepresentation("execute"));

        List<ResourceRepresentation> resources = new ArrayList<>();

        resources.add(new ResourceRepresentation("Resource D", scopes));
        resources.add(new ResourceRepresentation("Resource E", scopes));
        resources.add(new ResourceRepresentation("Resource F", scopes));

        resources.forEach(resource -> {
            Response response = getClient().authorization().resources().create(resource);
            response.close();
        });
    }

    /***It seems like there are a few issues with the code you provided:String scopeNames = (String) requestMap.get("scopes"); is retrieving a single string value from the requestMap using the key "scopes". If this value is a comma-separated list of scope names, you will need to split it into individual scope names.scopes.add(new ScopeRepresentation(scopeNames)); is trying to create a single scope representation object using the scopeNames string. If scopeNames contains multiple scope names, this will not work. Instead, you will need to loop through the individual scope names and create a separate ScopeRepresentation object for each.*/

    @PostMapping("/resources1")
    private void createResourcesAndScopes(@RequestBody Map<String, String> requestMap) throws IOException {
        String resourceName = requestMap.get("name");
        String scopeNames = requestMap.get("scopes");

        Set<ScopeRepresentation> scopes = new HashSet<>();

        if (scopeNames != null) {
            String[] scopeNameArray = scopeNames.split(",");
            for (String scopeName : scopeNameArray) {
                scopes.add(new ScopeRepresentation(scopeName.trim()));
            }
        }

        List<ResourceRepresentation> resources = new ArrayList<>();
        resources.add(new ResourceRepresentation(resourceName, scopes));

        resources.forEach(resource -> {
            Response response = getClient().authorization().resources().create(resource);
            response.close();
        });
    }

    @PostMapping("/resourcesUri")
    private void createResourcesAndScopesAndUri(@RequestBody Map<String, String> requestMap) throws IOException {
        String resourceName = requestMap.get("name");
        String scopeNames = requestMap.get("scopes");
        String uri = requestMap.get("uri");

        Set<ScopeRepresentation> scopes = new HashSet<>();

        if (scopeNames != null) {
            String[] scopeNameArray = scopeNames.split(",");
            for (String scopeName : scopeNameArray) {
                scopes.add(new ScopeRepresentation(scopeName.trim()));
            }
        }

        ResourceRepresentation resource = new ResourceRepresentation(resourceName, scopes);

        if (uri != null) {
            resource.setUris(Collections.singleton(uri));
        }

        Response response = getClient().authorization().resources().create(resource);
        response.close();
    }

    @GetMapping("/resourcesList")
    public List<Map<String, Object>> getAllResourcesWithNameScopeUri() {
        List<Map<String, Object>> resourcesList = new ArrayList<>();

        List<ResourceRepresentation> resources = getClient().authorization().resources().resources();
        for (ResourceRepresentation resource : resources) {
            Map<String, Object> resourceMap = new HashMap<>();
            resourceMap.put("name", resource.getName());
            resourceMap.put("uri", resource.getUri());
            List<String> scopeNames = new ArrayList<>();
            for (ScopeRepresentation scope : resource.getScopes()) {
                scopeNames.add(scope.getName());
            }
            resourceMap.put("scopes", scopeNames);
            resourcesList.add(resourceMap);
        }

        return resourcesList;
    }

    /**********************************************************************/
    @PostMapping("/resources/{resourceId}/scopes")
    public void addScopeToResource(@PathVariable String resourceId, @RequestBody Map<String, String> requestMap) throws IOException {
        String scopeName = requestMap.get("name");

        // Retrieve the resource by ID
        ResourceRepresentation resource = getClient().authorization().resources().resource(resourceId).toRepresentation();

        // Create the new scope and add it to the resource
        Set<ScopeRepresentation> scopes = resource.getScopes() != null ? resource.getScopes() : new HashSet<>();
        scopes.add(new ScopeRepresentation(scopeName));
        resource.setScopes(scopes);

        // Update the resource with the new scope
        getClient().authorization().resources().resource(resourceId).update(resource);
    }

    @PutMapping("/resources/{resourceId}")
    public void updateResource(@PathVariable String resourceId, @RequestBody Map<String, String> requestMap) throws IOException {
        String resourceName = requestMap.get("name");
        String uri = requestMap.get("uri");

        // Retrieve the resource by ID
        ResourceRepresentation resource = getClient().authorization().resources().resource(resourceId).toRepresentation();

        // Update the resource with the new name and URI
        resource.setName(resourceName);
        resource.setUri(uri);

        // Update the resource
        getClient().authorization().resources().resource(resourceId).update(resource);
    }

    @PostMapping("/resources/{resourceId}/url")
    public void addUrlToResource(@PathVariable String resourceId, @RequestBody Map<String, String> requestMap) throws IOException {
        String url = requestMap.get("url");

        // Retrieve the resource by ID
        ResourceRepresentation resource = getClient().authorization().resources().resource(resourceId).toRepresentation();

        // Set the new URL for the resource
        resource.setUri(url);

        // Update the resource with the new URL
        getClient().authorization().resources().resource(resourceId).update(resource);
    }

    /********************************************************************************/
    @DeleteMapping("/resources/{resourceId}/scopes/{scopeId}")
    public void deleteScopeFromResource(@PathVariable String resourceId, @PathVariable String scopeId) throws IOException {
        // Retrieve the resource by ID
        ResourceRepresentation resource = getClient().authorization().resources().resource(resourceId).toRepresentation();

        // Retrieve the scope by ID
        ScopeRepresentation scopeToDelete = null;
        for (ScopeRepresentation scope : resource.getScopes()) {
            if (scope.getId().equals(scopeId)) {
                scopeToDelete = scope;
                break;
            }
        }

        // Remove the scope from the resource
        if (scopeToDelete != null) {
            resource.getScopes().remove(scopeToDelete);

            // Update the resource without the deleted scope
            getClient().authorization().resources().resource(resourceId).update(resource);
        }
    }

    @DeleteMapping("/resources/{resourceId}/urls/{url}")
    public void deleteUrlFromResource(@PathVariable String resourceId, @PathVariable String url) throws IOException {
        // Retrieve the resource by ID
        ResourceRepresentation resource = getClient().authorization().resources().resource(resourceId).toRepresentation();

        // Remove the URL from the resource's list of URLs
        List<String> urls = new ArrayList<>(resource.getUris()); // convert Set<String> to List<String>
        urls.remove(url);
        resource.setUris(new HashSet<>(urls)); // convert List<String> to Set<String>

        // Update the resource with the new list of URLs
        getClient().authorization().resources().resource(resourceId).update(resource);
    }

    @GetMapping("/resources/{resourceId}")
    public ResourceRepresentation getResourceById(@PathVariable String resourceId) throws IOException {
        // Retrieve the resource by ID
        ResourceRepresentation resource = getClient().authorization().resources().resource(resourceId).toRepresentation();

        return resource;
    }

    @GetMapping("/resources")
    public void displayAllResources() throws IOException {
        List<ResourceRepresentation> resources = getClient().authorization().resources().resources();

        for (ResourceRepresentation resource : resources) {
            System.out.println("Resource ID: " + resource.getId());
            System.out.println("Resource Name: " + resource.getName());
            System.out.println("Resource Scopes: " + resource.getScopes());
            System.out.println("Resource URLs: " + resource.getUris());
            System.out.println("------------------------");
        }
    }

    @PostMapping("/permissions1")
    private static void createScopePermission(
        @RequestBody ResourceServerRepresentation settings,
        @RequestBody ResourceRepresentation resource,
        @RequestBody PolicyRepresentation policy,
        @RequestBody String scope
    ) {
        PolicyRepresentation permission = new PolicyRepresentation();
        permission.setName(resource.getName() + " Permission");
        permission.setType("scope");
        permission.setResources(new HashSet<>());
        permission.getResources().add(resource.getName());
        permission.setScopes(new HashSet<>());
        permission.getScopes().add(scope);
        permission.setPolicies(new HashSet<>());
        permission.getPolicies().add(policy.getName());

        settings.getPolicies().add(permission);
    }

    /*-------------------------------------------------------------------------------------------------------*/

    @PostMapping("/roles/{roleId}/attributesPath")
    public void addRoleAttribute(@PathVariable String roleId, @RequestBody Map<String, Object> attribute) {
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        String roleName = role.getName();
        //String attributeName = attribute.get("name").toString();
        String attributeName = "path";
        String attributeValue = attribute.get("value").toString();

        List<String> attributeList = role.getAttributes().get(attributeName);
        if (attributeList == null) {
            attributeList = new ArrayList<>();
        }

        if (attributeList.contains(attributeValue)) {
            attributeList.remove(attributeValue);
        }

        attributeList.add(attributeValue);

        role.getAttributes().put(attributeName, attributeList);
        keycloak.realm("google").roles().get(roleName).update(role);
    }

    @PostMapping("/roles/{roleId}/attributesPathDelete")
    public void deleteRoleAttribute(@PathVariable String roleId, @RequestBody Map<String, Object> attribute) {
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        String roleName = role.getName();
        // String attributeName = attribute.get("name").toString();
        String attributeName = "path";
        String attributeValue = attribute.get("value").toString();

        List<String> attributeList = role.getAttributes().get(attributeName);
        if (attributeList != null) {
            attributeList.remove(attributeValue);
            role.getAttributes().put(attributeName, attributeList);
            keycloak.realm("google").roles().get(roleName).update(role);
        }
    }

    @GetMapping("/roles/{roleId}/attributes/path")
    public List<String> getRoleAttributePath(@PathVariable String roleId) {
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        List<String> pathValues = (List<String>) role.getAttributes().get("path");
        //String firstPath = pathValues.get(0);
        // System.out.println(firstPath);
        return role.getAttributes().getOrDefault("path", new ArrayList<>());
    }

    @PostMapping("/roles/{roleId}/attributesPermission")
    public void addRoleAttributePermission(@PathVariable String roleId, @RequestBody Map<String, Object> attribute) {
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        String roleName = role.getName();
        //String attributeName = attribute.get("name").toString();
        String attributeName = "permission";
        String attributeValue = attribute.get("value").toString();

        List<String> attributeList = role.getAttributes().get(attributeName);
        if (attributeList == null) {
            attributeList = new ArrayList<>();
        }

        if (attributeList.contains(attributeValue)) {
            attributeList.remove(attributeValue);
        }

        attributeList.add(attributeValue);

        role.getAttributes().put(attributeName, attributeList);
        keycloak.realm("google").roles().get(roleName).update(role);
    }

    @PostMapping("/roles/{roleId}/attributesPermissionDelete")
    public void deleteRoleAttributePermission(@PathVariable String roleId, @RequestBody Map<String, Object> attribute) {
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        String roleName = role.getName();
        // String attributeName = attribute.get("name").toString();
        String attributeName = "permission";
        String attributeValue = attribute.get("value").toString();

        List<String> attributeList = role.getAttributes().get(attributeName);
        if (attributeList != null) {
            attributeList.remove(attributeValue);
            role.getAttributes().put(attributeName, attributeList);
            keycloak.realm("google").roles().get(roleName).update(role);
        }
    }

    @GetMapping("/roles/{roleId}/attributes/permission")
    public List<String> getRoleAttributePermission(@PathVariable String roleId) {
        RoleRepresentation role = keycloak.realm("google").rolesById().getRole(roleId);
        List<String> pathValues = (List<String>) role.getAttributes().get("permission");
        // String firstPath = pathValues.get(0);
        // System.out.println(firstPath);
        return role.getAttributes().getOrDefault("permission", new ArrayList<>());
    }

    @GetMapping("/rolesIds")
    public List<String> getRolesIds() {
        RealmResource realmResource = keycloak.realm("google");
        List<RoleRepresentation> roles = realmResource.roles().list();
        return roles.stream().map(RoleRepresentation::getId).collect(Collectors.toList());
    }

    @GetMapping("/rolesIdsNames")
    public Map<String, String> getRolesIdsAndNames() {
        RealmResource realmResource = keycloak.realm("google");
        List<RoleRepresentation> roles = realmResource.roles().list();

        return roles.stream().collect(Collectors.toMap(RoleRepresentation::getId, RoleRepresentation::getName));
    }

    @GetMapping("/configureSecurity")
    protected void configure(HttpSecurity http) throws Exception {
        // Retrieve all role IDs from Keycloak
        List<String> roleIds = getRolesIds();

        // Loop through each role ID and retrieve the associated paths and permissions from PathRepository
        for (String roleId : roleIds) {
            List<String> paths = getRoleAttributePath(roleId);
            List<String> permissions = getRoleAttributePermission(roleId);
            String roleName = getRoleById(roleId).getBody().getName();
            // Configure HttpSecurity for each path and permission
            for (String path : paths) {
                for (String permission : permissions) {
                    http
                        .authorizeRequests()
                        .antMatchers(path)
                        .access("hasRole('" + roleName + "')")
                        .and()
                        .authorizeRequests()
                        .antMatchers(permission)
                        .hasRole(roleName)
                        .and()
                        .csrf();
                }
            }
        }
    }

    /******************************************Restriction des roles version 1****************************************************************/

    @GetMapping(value = "/user/idAfterLogin")
    public ResponseEntity<String> getUserIdAfterLogin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = authentication.getName(); // Assuming the user ID is the username
        System.out.println("User ID@@@@@@@@@@@@@@@: " + userId);
        return ResponseEntity.ok(userId);
    }

    /* @GetMapping(value = "/user/idAfterLogin")
    public ResponseEntity<String> getUserIdAfterLogin(HttpServletRequest request) {
        String userId = request.getUserPrincipal().getName();
        System.out.println("User ID%%%%%%%%%%%%%%%%%%%%%%%%%%%%%: " + userId);
        return ResponseEntity.ok(userId);
    }*/

    public ResponseEntity<String> home(HttpServletRequest request) {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) request.getUserPrincipal();
        KeycloakPrincipal principal = (KeycloakPrincipal) token.getPrincipal();
        String userId = principal.getName();
        return ResponseEntity.ok(userId);
    }

    @GetMapping(value = "/user/userRoleAfterlogin")
    public ResponseEntity<List<String>> getUserRoleAfterlogin() {
        //  String userId = getUserIdAfterLogin().getBody().toString();
        String id = "";
        String userId = receiveAccountId(id).getBody().toString();
        System.out.println("user Is : @@@@@@@@@@@@@@@@@@@@@@@@@@" + userId);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        ResponseEntity<UserRepresentation> user = getUser(userId);
        String userName = user.getBody().getUsername();
        ResponseEntity<List<String>> listRole = getUserRoles(userName);
        List<String> roles = listRole.getBody();
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/RoleRestriction")
    public ResponseEntity<String> RoleRestriction() {
        ResponseEntity<List<String>> userRolesResponse = getUserRoleAfterlogin();

        Map<String, String> rolesMap = getRolesIdsAndNames();

        for (Map.Entry<String, String> entry : rolesMap.entrySet()) {
            String roleId1 = entry.getKey();
            String desiredRole = entry.getValue();

            List<String> ListPermission = getRoleAttributePermission(roleId1);
            List<String> ListPath = getRoleAttributePath(roleId1);
            for (String desiredPath : ListPath) {
                for (String desiredPermission : ListPermission) {
                    if (userRolesResponse.getStatusCode().is2xxSuccessful()) {
                        List<String> userRoles = userRolesResponse.getBody();
                        for (String userRole : userRoles) {
                            if (userRole.contains(desiredRole)) {
                                System.out.println("userRole **********************************:" + userRole);
                                if (userRole != null && !userRole.isEmpty()) {
                                    // Check if the user's role has permission for the given path
                                    RoleRepresentation roleUserLogin = keycloak.realm("google").roles().get(userRole).toRepresentation();
                                    if (roleUserLogin != null && roleUserLogin.getId() != null && !roleUserLogin.getId().isEmpty()) {
                                        String roleId = roleUserLogin.getId();
                                        List<String> attributePermissions = getRoleAttributePermission(roleId);
                                        List<String> attributePaths = getRoleAttributePath(roleId);
                                        System.out.println("attributePermissions***************** :" + attributePermissions);
                                        System.out.println("attributePaths****************************** :" + attributePaths);
                                        // Check if the desired path and permission are allowed for the current role
                                        if (
                                            !attributePaths.isEmpty() &&
                                            attributePaths.contains(desiredPath) &&
                                            attributePermissions.contains(desiredPermission)
                                        ) {
                                            // User has permission
                                            return ResponseEntity.ok("User has permission for the desired path and permission");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // User does not have permission
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("User does not have permission for the desired path and permission");
    }

    @GetMapping("/hasAuthority")
    public boolean hasAuthority() {
        ResponseEntity<String> roleRestrictionResponse = RoleRestriction();
        if (roleRestrictionResponse.getStatusCode().is2xxSuccessful()) {
            String message = roleRestrictionResponse.getBody();
            System.out.println("***************************");
            System.out.println("has role: " + message);
            return message.startsWith("User has permission");
        }
        return false;
    }

    /************************************************************************************************************************/

    @RequestMapping(value = "/functions", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<?> getControllerFunctions() {
        List<String> functionNames = new ArrayList<>();
        Class<?> controllerClass = this.getClass();
        Method[] methods = controllerClass.getDeclaredMethods();
        for (Method method : methods) {
            functionNames.add(method.getName());
        }
        return ResponseEntity.ok(functionNames);
    }

    @Autowired
    public AccountResource accountResource;

    @GetMapping("/accountId")
    public String getAccountId(Principal principal) {
        AdminUserDTO adminUser = accountResource.getAccount(principal);
        String id = adminUser.getId();
        System.out.println(id);
        return id;
    }

    /*@PostMapping("/accountReceived")
    public ResponseEntity<Void> receiveAccountId(@RequestParam("id") String id) {
        System.out.println("Received ID: " + id);             
        return ResponseEntity.ok().build();
    }*/

    @PostMapping("/accountReceived")
    public ResponseEntity<String> receiveAccountId(@RequestParam("id") String id) {
        System.out.println("Received ID: * *********** " + id);
        System.out.println(ResponseEntity.ok(id).getBody().toString());
        return ResponseEntity.ok(id);
    }

    @PostMapping("/assign-roles-based-on-group-membership1")
    public void assignRolesBasedOnGroupMembership1() throws JsonProcessingException {
        // Get all groups
        RealmResource realmResource = keycloak.realm("google");
        List<GroupRepresentation> groups = realmResource.groups().groups();
        // Iterate over each group
        for (GroupRepresentation group : groups) {
            String groupId = group.getId().toString();
            System.out.println("groupId__________________" + groupId + group.getName());
            System.out.println("groupName__________________" + group.getName());
            // Get the group members
            GroupResource groupResource = realmResource.groups().group(groupId);
            // Get the list of members in the group
            List<UserRepresentation> groupMembers = null;
            /**(((((((((((((((((((((((()))))))))))))))))))))))))*/
            try {
                groupMembers = groupResource.members();
                ObjectMapper objectMapper = new ObjectMapper();
                String json = objectMapper.writeValueAsString(groupMembers);
                System.out.println("group members: ====== " + json);
            } catch (InternalServerErrorException e) {
                System.err.println("Failed to retrieve group members for groupId: " + groupId);
                e.printStackTrace();
                continue; // Skip to the next group if an error occurs
            }
            if (groupMembers.isEmpty()) {
                continue; // Skip to the next group if there are no group members
            }
            // Get the roles associated with the group
            RoleScopeResource roleScopeResource = groupResource.roles().realmLevel();
            System.out.println("list group role +*+*+*+*+*+*+*" + roleScopeResource.listAll());
            // Get a list of all roles assigned to the group
            List<RoleRepresentation> groupRoles = roleScopeResource.listAll();
            if (groupRoles.isEmpty()) {
                continue; // Skip to the next group if there are no group roles
            }
            // Assign group roles to users
            for (UserRepresentation user : groupMembers) {
                String userId = user.getId();
                System.out.println("userName:--------" + user.getUsername().toString());
                // Get the user groups
                List<GroupRepresentation> userGroups = getUserGroups(userId);
                /****json****json**json***json**json**json**json**json**json**json**json**json**json**json***json***json**json***json**json***********/
                ObjectMapper objectMapper = new ObjectMapper();
                String json = objectMapper.writeValueAsString(userGroups);
                System.out.println("userGroups: ====== " + json);

                if (userGroups.isEmpty()) {
                    continue; // Skip to the next user if the user does not belong to any groups
                }
                // Check if the user is a member of the current group
                if (userGroups.stream().anyMatch(g -> g.getId().equals(groupId))) {
                    // Assign group roles to the user
                    for (RoleRepresentation role : groupRoles) {
                        assignRoleToUser(user.getUsername(), role);
                    }
                }
                /**********/
                // Remove roles not present in the groups of the user
                ResponseEntity<List<String>> userRolesResponse = getUserRoles(user.getUsername().toString());
                List<String> userRoles = userRolesResponse.getBody();
                if (userRoles != null) {
                    for (String role : userRoles) {
                        if (!groupRoles.stream().anyMatch(r -> r.getName().equals(role))) {
                            Map<String, String> roleData = new HashMap<>();
                            roleData.put("username", user.getUsername());
                            roleData.put("roleName", role);
                            deleteRoleFromUser(roleData);
                        }
                    }
                }
                /******/
                List<RoleRepresentation> list = showRolesForGroup(groupId);
                ResponseEntity<List<String>> list1 = getUserRoles(user.getUsername().toString());
                System.out.println("group Name :" + group.getName() + "list role of group >>>>>>>>>" + list);
                System.out.println("user Name :" + user.getUsername().toString() + "list of user roles  >>>>>>>>" + list1);
            }
        }
        //keycloak.close();
    }

    private void assignRoleToUser(String userId, RoleRepresentation role) {
        Map<String, String> roleData = new HashMap<>();
        roleData.put("roleName", role.getName());
        roleData.put("username", userId);
        ResponseEntity<String> response = addRoleToUser(roleData);
        if (response.getStatusCode() != HttpStatus.OK) {}
    }

    /***************************************Role restriction version 2***************************************************************/
    /* 
    @GetMapping(value = "/user/idAfterLogin1")
    public ResponseEntity<String> getUserIdAfterLogin1() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = authentication.getName(); // Assuming the user ID is the username
        System.out.println("User ID in idAfterlogin @@@@@@@@@@@@@@@: " + userId);
        return ResponseEntity.ok(userId);
    }

    @GetMapping(value = "/user/userRoleAfterlogin1")
    public ResponseEntity<List<String>> getUserRoleAfterlogin1(String userId) {
        String userId1 = getUserIdAfterLogin1().getBody().toString();
            userId = userId1;
        if (userId == null || userId.isEmpty()) {
        } else if (userId1.equals("anonymousUser")) {
            userId = userId; // Use the userId parameter passed to the method
        }
        System.out.println("user Is: @@@@@@@@@@@@@@@@@@@@@@@@@@" + userId);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        ResponseEntity<UserRepresentation> user = getUser(userId);
        String userName = user.getBody().getUsername();
        ResponseEntity<List<String>> listRole = getUserRoles(userName);
        List<String> roles = listRole.getBody();
        return ResponseEntity.ok(roles);
    }

    public ResponseEntity<List<String>> getUserPathsAfterLogin1(String userId) {
        ResponseEntity<List<String>> userRolesResponse = getUserRoleAfterlogin1(userId);
        if (userRolesResponse.getStatusCode().is2xxSuccessful()) {
            List<String> userRoles = userRolesResponse.getBody();
            List<String> paths = new ArrayList<>();

            for (String role : userRoles) {
                RoleRepresentation roleRep = keycloak.realm("google").roles().get(role).toRepresentation();
                List<String> rolePathsResponse = getRoleAttributePath(roleRep.getId().toString());
                if (!rolePathsResponse.isEmpty()) {
                    paths.addAll(rolePathsResponse);
                }
            }

            return ResponseEntity.ok(paths);
        }

        // Failed to retrieve user roles
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } */
    /*******************************************************************************************************/

    @GetMapping(value = "/user/idAfterLogin1")
    public ResponseEntity<String> getUserIdAfterLogin1() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = authentication.getName(); // Assuming the user ID is the username
        return ResponseEntity.ok(userId);
    }

    @GetMapping(value = "/user/userRoleAfterlogin1")
    public ResponseEntity<List<String>> getUserRoleAfterlogin1(String userId) {
        String userId1 = getUserIdAfterLogin1().getBody().toString();
        if (userId == null || userId.isEmpty()) {
            userId = userId1;
        } else if (userId1.equals("anonymousUser")) {
            userId = userId; // Use the userId parameter passed to the method
        }
        System.out.println("user Is: @@@@@@@@@@@@@@@@@@@@@@@@@@" + userId);
        ResponseEntity<UserRepresentation> user;
        user = getUser(userId);
        System.out.println("user id: @@@@@@@@@@@@@@@@@@@@@@@@@@" + userId);
        String userName = user.getBody().getUsername();
        ResponseEntity<List<String>> listRole = getUserRoles(userName);
        List<String> roles = listRole.getBody();
        if (listRole.getStatusCode().is2xxSuccessful()) {
            List<String> paths = new ArrayList<>();
            for (String role : roles) {
                RoleRepresentation roleRep = keycloak.realm("google").roles().get(role).toRepresentation();
                List<String> rolePathsResponse = getRoleAttributePath(roleRep.getId().toString());
                if (!rolePathsResponse.isEmpty()) {
                    paths.addAll(rolePathsResponse);
                }
            }
            return ResponseEntity.ok(paths);
        }
        // Failed to retrieve user roles
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/yourEndpoint")
    public boolean getAuthorizationResult(ProceedingJoinPoint joinPoint) {
        try {
            boolean result = authorizationStatus.getAuthorityStatus();
            System.out.println(result + "+++++++++++++++");
            return result;
        } catch (Throwable e) {
            System.out.println("Error occurred during authorization check: " + e.getMessage());
            return false;
        }
    }
    
  /***************************************synchronize keycloak Users With LDAP***********************************************************/  
   
    @GetMapping("/usersSynch")
    public void synchronizeKeycloakUsersWithLDAP() {
        RealmResource realmResource = keycloak.realm("google");
        List<UserRepresentation> users = realmResource.users().list();
        try {
            DirContext ldapContext = getLDAPContext();
            for (UserRepresentation user : users) {
                // Map user attributes to LDAP attributes
                Attributes attributes = new BasicAttributes();
                attributes.put(new BasicAttribute("uid", user.getUsername()));
                attributes.put(new BasicAttribute("cn", user.getFirstName()));
                attributes.put(new BasicAttribute("sn", user.getLastName()));
                attributes.put(new BasicAttribute("mail", user.getEmail()));
                attributes.put(new BasicAttribute("postalCode", user.firstAttribute("postalCode")));
                attributes.put(new BasicAttribute("street", user.firstAttribute("street")));
                attributes.put(new BasicAttribute("telephoneNumber", user.firstAttribute("phonenumber")));
              //  attributes.put(new BasicAttribute("matricule", user.firstAttribute("matricule")));
               // attributes.put(new BasicAttribute("fax", user.firstAttribute("fax")));
                //attributes.put(new BasicAttribute("arabicName", user.firstAttribute("arabicName")));
                // Add the objectClass attribute
                attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
                // Create or update the LDAP entry for the user
                ldapContext.rebind("uid=" + user.getUsername() + "," + "o=XteUsers,dc=xtensus,dc=com", null, attributes);
            }
            ldapContext.close();
        } catch (NamingException e) {
            e.printStackTrace();
            // Handle LDAP synchronization error
        }
    }
    private DirContext getLDAPContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=xtensus,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, "ikhlass");
        return new InitialDirContext(env);
    }

/********************************************synchronize LDAP Users With keycloak*****************************************************/
    
    @GetMapping("/usersSynch1")
    public void synchronizeLDAPusersWithKeycloak() {
        try {
            DirContext ldapContext = getLDAPContext();
            NamingEnumeration<SearchResult> searchResults = searchLDAPUsers(ldapContext);
            while (searchResults.hasMore()) {
                SearchResult searchResult = searchResults.next();
                Attributes attributes = searchResult.getAttributes();
                // Extract user attributes from LDAP attributes
                String username = extractAttributeValue(attributes, "uid");
                String firstName = extractAttributeValue(attributes, "givenName");
                String lastName = extractAttributeValue(attributes, "sn");
                String email = extractAttributeValue(attributes, "mail");
                String telephoneNumber = extractAttributeValue(attributes, "telephoneNumber");
                String postalCode = extractAttributeValue(attributes, "postalCode");
                String street = extractAttributeValue(attributes, "street");
                System.out.println("telephoneNumber: " + telephoneNumber);
                // Check if the user already exists in Keycloak
                RealmResource realmResource = keycloak.realm("google");
                UserResource existingUser = findExistingUserInKeycloak(realmResource, username);
                if (existingUser == null) {
                    // User does not exist in Keycloak, create a new user representation
                    UserRepresentation newUser = new UserRepresentation();
                    newUser.setUsername(username);
                    newUser.setFirstName(firstName);
                    newUser.setLastName(lastName);
                    newUser.setEmail(email);
                    newUser.setEnabled(true);
                    // Set the telephoneNumber attribute
                    Map<String, List<String>> attributesMap = new HashMap<>();
                    attributesMap.put("phonenumber", List.of(telephoneNumber));
                    newUser.setAttributes(attributesMap);
                    // Add the user to Keycloak
                    realmResource.users().create(newUser);
                    System.out.println("Created new user in Keycloak: ********************" + newUser.getUsername() + newUser.getId());
                } else {
                    // User exists in Keycloak, update the telephoneNumber attribute
                    UserRepresentation userRepresentation = existingUser.toRepresentation();
                    addTelephoneNumber2(userRepresentation.getId().toString(),telephoneNumber , postalCode,street );
                   // userRepresentation.getAttributes().put("telephoneNumber", List.of(telephoneNumber));
                   // existingUser.update(userRepresentation);
                    System.out.println("Updated user in Keycloak: *****************" + userRepresentation.getUsername());
                }
            }
            ldapContext.close();
        } catch (NamingException e) {
            e.printStackTrace();
            // Handle LDAP synchronization error
        }
    }

    public void addTelephoneNumber2(String userId, String telephoneNumber,String postalCode , String street  ) {
        RealmResource realmResource = keycloak.realm("google");
        UserResource userResource = realmResource.users().get(userId);
        UserRepresentation userRepresentation = userResource.toRepresentation();
        userRepresentation.getAttributes().put("phonenumber", List.of(telephoneNumber));
        userRepresentation.getAttributes().put("postalCode", List.of(postalCode));
        userRepresentation.getAttributes().put("street", List.of(street));
        userResource.update(userRepresentation);
    }

    
    private NamingEnumeration<SearchResult> searchLDAPUsers(DirContext ldapContext) throws NamingException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchBase = "o=XteUsers,dc=xtensus,dc=com";
        String searchFilter = "(objectClass=inetOrgPerson)";
        return ldapContext.search(searchBase, searchFilter, searchControls);
    }
    private String extractAttributeValue(Attributes attributes, String attributeName) throws NamingException {
        Attribute attribute = attributes.get(attributeName);
        if (attribute != null) {
            return attribute.get().toString();
        }
        return null;
    }
    private UserResource findExistingUserInKeycloak(RealmResource realmResource, String username) {
        List<UserRepresentation> existingUsers = realmResource.users().search(username);
        if (existingUsers != null && !existingUsers.isEmpty()) {
            String existingUserId = existingUsers.get(0).getId();
            return realmResource.users().get(existingUserId);
        }
        return null;
    }
    
    /**********************************************Synchronise Groups in keycloak to ldap ************************************************************/
    @GetMapping("/groupsSynch")
    public void synchronizeGroupsWithLDAP() {
        try {
            DirContext ldapContext = getLDAPContext();
            RealmResource realmResource = keycloak.realm("google");
            List<GroupRepresentation> groups = realmResource.groups().groups();
            for (GroupRepresentation group : groups) {
                if (groupExistsInLDAP(ldapContext, group)) {
                    continue; // Skip to the next group
                }
                Attributes attributes = new BasicAttributes();
                attributes.put(new BasicAttribute("cn", group.getName()));
                System.out.println("***************" + getGroupDescription(group.getId()));
                attributes.put(new BasicAttribute("description", getGroupDescription(group.getId())));
              //  attributes.put(new BasicAttribute("description", "111"));
                attributes.put(new BasicAttribute("objectClass", "groupOfNames"));
                // Set the members of the group
                List<String> memberDNs = getMemberDNs(realmResource, group);
                if (memberDNs.isEmpty()) {
                    // Add a default user to the group if no members found
                    memberDNs.add("uid=defaultuser,o=XteGroups,dc=xtensus,dc=com");
                }
                Attribute memberAttribute = new BasicAttribute("member");
                for (String memberDN : memberDNs) {
                    memberAttribute.add(memberDN);
                }
                attributes.put(memberAttribute);
                // Specify the distinguished name for the new group entry
                String newGroupDN = "cn=" + group.getName() + ",o=XteGroups,dc=xtensus,dc=com";
                // Create the new group entry in LDAP
                ldapContext.createSubcontext(newGroupDN, attributes);
            }
            ldapContext.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    private List<String> getMemberDNs(RealmResource realmResource, GroupRepresentation group) {
        List<String> memberDNs = new ArrayList<>();
        List<UserRepresentation> members = realmResource.groups().group(group.getId()).members();
        // Convert the user representations to member DNs
        for (UserRepresentation member : members) {
            String memberDN = "uid=" + member.getUsername() + ",o=XteGroups,dc=xtensus,dc=com";
            memberDNs.add(memberDN);
        }
        return memberDNs;
    }
    private boolean groupExistsInLDAP(DirContext ldapContext, GroupRepresentation group) throws NamingException {
        String groupDN = "cn=" + group.getName() + ",o=XteGroups,dc=xtensus,dc=com";
        try {
            ldapContext.getAttributes(groupDN);
            return true; // Group exists in LDAP
        } catch (NameNotFoundException e) {
            return false; // Group does not exist in LDAP
        }
    }
    public String getGroupDescription(String groupId) {
        RealmResource realmResource = keycloak.realm("google");
        GroupResource groupResource = realmResource.groups().group(groupId);
        GroupRepresentation groupRepresentation = groupResource.toRepresentation();
        String description = null;
        if (groupRepresentation.getAttributes() != null) {
            description = groupRepresentation.getAttributes().get("description").get(0);
        }
        return description;
    }

/*************************************************add goup From LDAP To Keycloak*************************************************************/
    @GetMapping("/groupsSynch1")
    public void addGroupsFromLDAPToKeycloak() {
    	 try {
    	        RealmResource realmResource = keycloak.realm("google");
    	        List<String> ldapGroupNames = getLDAPGroupNames();
                  System.out.println("ldapGroupNames" + ldapGroupNames);
    	        for (String ldapGroupName : ldapGroupNames) {
    	            if (groupExistsInKeycloak(realmResource, ldapGroupName)) {
    	                continue; // Skip to the next group
    	            }
    	            GroupRepresentation group = new GroupRepresentation();
    	            group.setName(ldapGroupName);
                    // Retrieve and set the description of the group from LDAP
                    String groupDescription = getDescriptionFromLDAP(ldapGroupName);
                    // Set additional group attributes as needed
                    if (groupDescription != null && !groupDescription.isEmpty()) {
                        Map<String, List<String>> attributes = new HashMap<>();
                        attributes.put("description", Collections.singletonList(groupDescription));
                        group.setAttributes(attributes);
                    }
    	            realmResource.groups().add(group);
    	        }
    	    } catch (Exception e) {
    	        e.printStackTrace();
    	    } finally {
    	       // keycloak.close();
    	    }
    	}
    private List<String> getLDAPGroupNames() throws NamingException {
        List<String> ldapGroupNames = new ArrayList<>();
        // Query LDAP to retrieve the group names
        // Example LDAP query to retrieve group names
        DirContext ldapContext = getLDAPContext();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchFilter = "(&(objectClass=groupOfNames))";
        NamingEnumeration<SearchResult> results = ldapContext.search("o=XteGroups,dc=xtensus,dc=com", searchFilter, searchControls);
        while (results.hasMore()) {
            SearchResult result = results.next();
            Attributes attributes = result.getAttributes();
            Attribute groupAttribute = attributes.get("cn");
            if (groupAttribute != null) {
                String ldapGroupName = (String) groupAttribute.get();
                ldapGroupNames.add(ldapGroupName);
            }
        }
        ldapContext.close();
        return ldapGroupNames;
    }
    private boolean groupExistsInKeycloak(RealmResource realmResource, String groupName) {
        // Check if the group exists in Keycloak
        List<GroupRepresentation> groups = realmResource.groups().groups();
        for (GroupRepresentation group : groups) {
        	System.out.println("group" + group.getName() );
            if (group.getName().equals(groupName)) {
                return true;
            }
        }
        return false;
    }
    @GetMapping("/khaled/{ldapGroupName}")
    public String getDescriptionFromLDAP(@PathVariable String ldapGroupName) throws NamingException {
        String description = null;
        DirContext ldapContext = getLDAPContext();
        try {
            String searchFilter = "(cn=" + ldapGroupName + ")";
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[] { "description" });
            NamingEnumeration<SearchResult> searchResults = ldapContext.search("o=XteGroups,dc=xtensus,dc=com", searchFilter, searchControls);
            if (searchResults.hasMore()) {
                SearchResult searchResult = searchResults.next();
                Attributes attributes = searchResult.getAttributes();
                if (attributes != null) {
                    Attribute descriptionAttribute = attributes.get("description");
                    if (descriptionAttribute != null) {
                        description = (String) descriptionAttribute.get();
                    }
                }
            }
        } finally {
            // Close the LDAP context
            ldapContext.close();
        }

        return description;
    }

/*************************************************synchronize keycloak Roles With LDAP*****************************************************************/
    @GetMapping("/rolesSynch")
    public void synchronizeRolesWithLDAP() {
        try {
            DirContext ldapContext = getLDAPContext();
            RealmResource realmResource = keycloak.realm("google");
            // Get the list of roles from Keycloak
            List<RoleRepresentation> roles = realmResource.roles().list();
            for (RoleRepresentation role : roles) {
                // Check if the role already exists in LDAP
                if (roleExistsInLDAP(ldapContext, role)) {
                    continue; // Skip to the next role
                }
                // Create the role entry in LDAP
                Attributes attributes = new BasicAttributes();
                attributes.put(new BasicAttribute("cn", role.getName()));
                // Check if the description attribute is null
                if (role.getDescription() != null) {
                    attributes.put(new BasicAttribute("description", role.getDescription()));
                } else {
                    // Provide a default value for the description
                    attributes.put(new BasicAttribute("description", "Default Description"));
                }
                attributes.put(new BasicAttribute("objectClass", "groupOfNames"));
                // Set the members of the role
                List<String> memberDNs = getMemberDNs(realmResource, role);
                if (memberDNs.isEmpty()) {
                    // Add a default user to the role if no members found
                    memberDNs.add("uid=defaultuser,o=XteDroits,dc=xtensus,dc=com");
                }
                Attribute memberAttribute = new BasicAttribute("member");
                for (String memberDN : memberDNs) {
                    memberAttribute.add(memberDN);
                }
                attributes.put(memberAttribute);
                // Specify the distinguished name for the new role entry
                String newRoleDN = "cn=" + role.getName() + ",o=XteDroits,dc=xtensus,dc=com";
                // Create the new role entry in LDAP
                ldapContext.createSubcontext(newRoleDN, attributes);
            }
            ldapContext.close();
        } catch (NamingException e) {
            e.printStackTrace();
            // Handle LDAP synchronization error
        }
    }

    private List<String> getMemberDNs(RealmResource realmResource, RoleRepresentation role) {
        List<String> memberDNs = new ArrayList<>();
        // Retrieve the role members from Keycloak
        Set<UserRepresentation> members = realmResource.roles().get(role.getName()).getRoleUserMembers();
       // List<UserRepresentation> members1 = realmResource.rolesById().getRole(role.getId()).get;
        // Convert the user representations to member DNs
        for (UserRepresentation member : members) {
            String memberDN = "uid=" + member.getUsername() + ",o=XteDroits,dc=xtensus,dc=com";
            memberDNs.add(memberDN);
        }
        return memberDNs;
    }
    private boolean roleExistsInLDAP(DirContext ldapContext, RoleRepresentation role) throws NamingException {
        String roleDN = "cn=" + role.getName() + ",o=XteDroits,dc=xtensus,dc=com";
        try {
            ldapContext.getAttributes(roleDN);
            return true; // Role exists in LDAP
        } catch (NameNotFoundException e) {
            return false; // Role does not exist in LDAP
        }
    }
   /*****************************************synchronize Roles LDAP with keycloak ****************************************************/
    @GetMapping("/rolesSynch1")
    public void synchronizeRolesWithLDAP1() {
        try {
            DirContext ldapContext = getLDAPContext();
            RealmResource realmResource = keycloak.realm("google");
            // Get the list of roles from LDAP
            System.out.println("**************"  );
            List<RoleRepresentation> ldapRoles = getLDAPRoles(ldapContext);
            for (RoleRepresentation ldapRole : ldapRoles) {
                // Check if the role already exists in Keycloak
                if (roleExistsInKeycloak(realmResource, ldapRole)) {
                    continue; // Skip to the next role
                }
                // Create the role entry in Keycloak
                RoleRepresentation newRole = new RoleRepresentation();
                newRole.setName(ldapRole.getName());
                // Set additional attributes as needed
                newRole.setDescription(getRoleDescriptionFromLDAP(ldapRole.getName()));
                System.out.println("**************"  + getRoleDescriptionFromLDAP(ldapRole.getName()) );
                // Add the role to Keycloak
                realmResource.roles().create(newRole);
                // Set the members of the role
                List<String> memberDNs = getMemberDNs(ldapContext, ldapRole);
                for (String memberDN : memberDNs) {
                    String username = getUsernameFromDN(memberDN);
                    // Retrieve the user from Keycloak
                    List<UserRepresentation> users = realmResource.users().search(username);
                    if (!users.isEmpty()) {
                        UserRepresentation user = users.get(0);
                        // Assign the role to the user
                        realmResource.users().get(user.getId()).roles().realmLevel().add(Arrays.asList(new RoleRepresentation[]{newRole}));
                    }
                }
            }

            ldapContext.close();
        } catch (NamingException e) {
            e.printStackTrace();
            // Handle LDAP synchronization error
        }
    }

    private List<RoleRepresentation> getLDAPRoles(DirContext ldapContext) throws NamingException {
        List<RoleRepresentation> ldapRoles = new ArrayList<>();
        // Search for role entries in LDAP
        NamingEnumeration<SearchResult> searchResults = ldapContext.search("o=XteDroits,dc=xtensus,dc=com", "(objectClass=groupOfNames)", new SearchControls());
        while (searchResults.hasMore()) {
            SearchResult searchResult = searchResults.next();
            Attributes attributes = searchResult.getAttributes();
            // Retrieve the role name
            String roleName = attributes.get("cn").get().toString();
            RoleRepresentation role = new RoleRepresentation();
            role.setName(roleName);
            ldapRoles.add(role);
        }
        return ldapRoles;
    }
    private List<String> getMemberDNs(DirContext ldapContext, RoleRepresentation ldapRole) throws NamingException {
        List<String> memberDNs = new ArrayList<>();
        // Retrieve the members of the role from LDAP
        Attributes attributes = ldapContext.getAttributes("cn=" + ldapRole.getName() + ",o=XteDroits,dc=xtensus,dc=com");
        Attribute memberAttribute = attributes.get("member");
        if (memberAttribute != null) {
            NamingEnumeration<?> memberEnumeration = memberAttribute.getAll();
            while (memberEnumeration.hasMore()) {
                String memberDN = memberEnumeration.next().toString();
                memberDNs.add(memberDN);
            }
        }
        return memberDNs;
    }
    private boolean roleExistsInKeycloak(RealmResource realmResource, RoleRepresentation ldapRole) {
        List<RoleRepresentation> keycloakRoles = realmResource.roles().list();
        for (RoleRepresentation role : keycloakRoles) {
            if (role.getName().equals(ldapRole.getName())) {
                return true; // Role exists in Keycloak
            }
        }
        return false; // Role does not exist in Keycloak
    }
    private String getUsernameFromDN(String memberDN) {
        String[] parts = memberDN.split(",");
        for (String part : parts) {
            if (part.startsWith("uid=")) {
                return part.substring(4);
            }
        }
        return null; // Invalid member DN format
    }

    @GetMapping("/roles/{ldapRoleName}/description")
    public String getRoleDescriptionFromLDAP(@PathVariable String ldapRoleName) throws NamingException {
        String description = null;
        DirContext ldapContext = getLDAPContext();
        try {
            String searchFilter = "(cn=" + ldapRoleName + ")";
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchControls.setReturningAttributes(new String[] { "description" });
            NamingEnumeration<SearchResult> searchResults = ldapContext.search("o=XteDroits,dc=xtensus,dc=com", searchFilter, searchControls);
            if (searchResults.hasMore()) {
                SearchResult searchResult = searchResults.next();
                Attributes attributes = searchResult.getAttributes();
                if (attributes != null) {
                    Attribute descriptionAttribute = attributes.get("description");
                    if (descriptionAttribute != null) {
                        description = (String) descriptionAttribute.get();
                    }
                }
            }
        } finally {
            ldapContext.close();
        }
        return description;
    }



    
}
