package com.xtensus.passosyf.web.rest;

import java.lang.reflect.Method;
import java.nio.file.AccessDeniedException;
import java.util.List;
import javax.servlet.http.HttpSession;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class AuthorizationAspect {

    private UserController userController;
    private AuthorizationStatus authorizationStatus;

    @Autowired
    private HttpSession httpSession;

    @Autowired
    public AuthorizationAspect(UserController userController, AuthorizationStatus authorizationStatus) {
        this.userController = userController;
        this.authorizationStatus = authorizationStatus;
    }

    /**In the case of a circular dependency, one approach to breaking the cycle is to use setter injection or field injection instead of constructor injection for one of the beans. **/
    /*@Autowired
    public void setUserController(UserController userController) {
        this.userController = userController;
    }*/

    @Around("@annotation(com.xtensus.passosyf.web.Authorize) && execution(* *(..))")
    public Object checkAuthorization(ProceedingJoinPoint joinPoint) throws Throwable {
        //to get the method name where we inject Authorize
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        String methodName = method.getName();
        // Get the list of permissions for the user
        String id = "";
        List<String> userPermissions = userController.getUserRoleAfterlogin1(id).getBody();
        // Check if the method name is in the list of permissions
        if (userPermissions.contains(methodName)) {
            setResult(true);
            authorizationStatus.setAuthorityStatus(true);
            System.out.println(getReslt() + "+++++++++++++++++++");
            return joinPoint.proceed();
        } else {
            System.out.println("User does not have the required permission.");
            setResult(false);
            authorizationStatus.setAuthorityStatus(false);
            System.out.println(getReslt() + "+++++++++++++++++++");
            return null;
        }
    }

    private static boolean result;

    public void setResult(boolean result) {
        this.result = result;
    }

    public boolean getReslt() {
        return result;
    }
}
/*
	@Autowired
    public AuthorizationAspect(UserController userController) {
        this.userController = userController;
    }

    @Around("@annotation(com.xtensus.passosyf.web.Authorize) && execution(* *(..))")
    public Object checkAuthorization(ProceedingJoinPoint joinPoint) throws Throwable {
    	//to get the method name where we inject Authorize
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        String methodName = method.getName();

        // Get the list of permissions for the user
        List<String> userPermissions = getUserPermissions();

        // Check if the method name is in the list of permissions
        if (userPermissions.contains(methodName)) {
            // User has the required permission, proceed with the method execution
            return joinPoint.proceed();
        } else {
            // User does not have the required permission
           // throw new AccessDeniedException("User does not have the required permission.");
        	 System.out.println("User does not have the required permission.");
             return null;
        }
    }

    private List<String> getUserPermissions() {
        // Retrieve the permissions for the current user from the UserController
        String userId = getCurrentUserId();
        return userController.getUserPathsAfterLogin1(userId).getBody();
    }

    private String getCurrentUserId() {
        String userId = userController.getUserIdAfterLogin1().getBody().toString();
        return userId;
    }

}*/
/*
@Autowired
public AuthorizationAspect(UserController userController) {
    this.userController = userController;
}

@Around("@annotation(com.xtensus.passosyf.web.Authorize) && execution(* *(..))")
public Object checkAuthorization(ProceedingJoinPoint joinPoint) throws Throwable {
    // Perform authorization check here
    boolean hasAuthority = hasAuthority();

    if (hasAuthority) {
        // User has the required authority, proceed with the method execution
        return joinPoint.proceed();
    } else {
        // User does not have the required authority
        System.out.println("User does not have the required authority.");
        // Handle the unauthorized access
        // For example, return an error response or throw an exception
        return null;
    }
}

private final UserController userController;

private boolean hasAuthority() {
    return this.userController.hasAuthority();
} */
/*
@Autowired
public AuthorizationAspect(UserController userController) {
    this.userController = userController;
}

@Around("@annotation(com.xtensus.passosyf.web.Authorize) && execution(* *(..))")
public Object checkAuthorization(ProceedingJoinPoint joinPoint) throws Throwable {
    // Perform authorization check here
	String id = "";
    boolean hasAuthority = hasAuthority(id);

    if (hasAuthority) {
        // User has the required authority, proceed with the method execution
        return joinPoint.proceed();
    } else {
        // User does not have the required authority
        System.out.println("User does not have the required authority.");
        // Handle the unauthorized access
        // For example, return an error response or throw an exception
        return null;
    }
}

private final UserController userController;

private boolean hasAuthority(String id) {
    return this.userController.hasAuthority1(id);
}*/
