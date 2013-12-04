package net.twomini.authservice.resources;

import com.google.common.base.Strings;
import net.twomini.authservice.data.*;
import net.twomini.authservice.data.dto.ServiceDetails;
import net.twomini.authservice.data.dto.UserDetails;
import com.yammer.metrics.annotation.Timed;
import net.twomini.authservice.data.dto.UserNavDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.net.URI;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    private static final Logger L = LoggerFactory.getLogger(AuthResource.class);

    private static CacheControl NO_CACHE_CONTROL = null;
    static {
        NO_CACHE_CONTROL = new CacheControl();
        NO_CACHE_CONTROL.setMaxAge(0);
        NO_CACHE_CONTROL.setMustRevalidate(true);
        NO_CACHE_CONTROL.setNoCache(true);
        NO_CACHE_CONTROL.setPrivate(true);
        NO_CACHE_CONTROL.setNoStore(true);
        NO_CACHE_CONTROL.setNoTransform(true);
    }

    private DataStore dataStore;

    private String cookieDomainName;
    private Boolean cookieSecureOnly;
    private String serviceBaseURL;
    private String salt;

    public URI LOGIN_HTML = null;
    public URI LANDING_HTML = null;
    public URI PERMISSION_DENIED_HTML = null;

    public AuthResource(DataStore dataStore,
                        String cookieDomainName, Boolean cookieSecureOnly,
                        String serviceBaseURL,
                        String salt) {
        this.dataStore = dataStore;
        this.cookieDomainName = cookieDomainName;
        this.cookieSecureOnly = cookieSecureOnly;
        this.serviceBaseURL = serviceBaseURL;
        this.salt = salt;

        try {
            LOGIN_HTML = new URI(serviceBaseURL + "login.html");
            LANDING_HTML = new URI(serviceBaseURL);
            PERMISSION_DENIED_HTML = new URI(serviceBaseURL + "permissionDenied.html");
        } catch(Exception e) {
            L.error("Error when initializing the URI's in the AuthResource", e);
        }
    }

    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getLandingView(@CookieParam("authUser") String token, @QueryParam("message") String message) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(token);
            if (verifiedUserToken == null) {
                return Response.seeOther(LOGIN_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
            return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new LandingView(verifiedUserToken, message)).build();
        } catch (Exception e) {
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }
    }

    @Path("login.html")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getLoginView(@QueryParam("destination") String destination, @QueryParam("message") String message) {
        return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new LoginView(destination, message)).build();
    }

    @GET
    @Timed
    @Path("logout.html")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"application/json"})
    public Response logout(@CookieParam("authUser") String token) {
        logoutUserToken(token);
        return Response.seeOther(LOGIN_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
    }

    @Path("permissionDenied.html")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getPermissionDeniedView(@CookieParam("authUser") String token) {
        try {
            UserToken verifiedUserToken = null;
            if (token != null) {
                verifiedUserToken = doVerifyUserToken(token);
            }
            return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new PermissionDeniedView(verifiedUserToken)).build();
        } catch (Exception e) {
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }

    }

    @Path("createUser.html")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getCreateUserView(@CookieParam("authUser") String token, @QueryParam("message") String message) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(token);

            //Make sure they are logged in
            if (verifiedUserToken == null) {
                return Response.seeOther(new URI(LOGIN_HTML.toString() + "?destination=" + URLEncoder.encode(serviceBaseURL + "createUser.html", "utf8"))).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
            //Make sure they have the useradmin role
            if (!verifiedUserToken.userAccount.hasRole("UserAdmin")) {
                return Response.seeOther(PERMISSION_DENIED_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }

            List<Role> assignableRoles = new ArrayList<Role>();
            for (Role role : dataStore.getRoles()) {
                if (isRoleAssignableByUser(role, verifiedUserToken)) {
                    assignableRoles.add(role);
                }
            }
            return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new CreateUserView(verifiedUserToken, assignableRoles, message)).build();

        } catch (Exception e) {
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }
    }

    @Path("manageUsers.html")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getManageUserView(@CookieParam("authUser") String token, @QueryParam("message") String message) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(token);

            //Make sure they are logged in
            if (verifiedUserToken == null) {
                return Response.seeOther(new URI(LOGIN_HTML.toString() + "?destination=" + URLEncoder.encode(serviceBaseURL + "manageUsers.html", "utf8"))).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
            //Make sure they have the useradmin role
            if (!verifiedUserToken.userAccount.hasRole("UserAdmin")) {
                return Response.seeOther(PERMISSION_DENIED_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }

            List<UserAccount> users = dataStore.getUsers();

            return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new ManageUserView(verifiedUserToken, users, message)).build();

        } catch (Exception e) {
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }
    }

    @Path("editUser.html")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getEditUserView(@CookieParam("authUser") String token, @QueryParam("message") String message, @QueryParam("userName") String userName) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(token);

            //Make sure they are logged in
            if (verifiedUserToken == null) {
                return Response.seeOther(new URI(LOGIN_HTML.toString() + "?destination=" + URLEncoder.encode(serviceBaseURL + "editUser.html?userName="+userName, "utf8"))).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
            //Make sure they have the useradmin role
            if (!verifiedUserToken.userAccount.hasRole("UserAdmin")) {
                return Response.seeOther(PERMISSION_DENIED_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }

            //Make sure there is a user parameter
            if (Strings.isNullOrEmpty(userName)){
                return Response.seeOther(new URI(serviceBaseURL+"manageUsers.html?message=" + URLEncoder.encode("Woops, no user was selected to edit","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Check that the user is a real user
            UserAccount user = dataStore.getUser(userName);
            if (user==null) {
                return Response.seeOther(new URI(serviceBaseURL + "manageUsers.html?message=" + URLEncoder.encode("Woops, invalid user was selected to edit", "utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            List<Role> assignableRoles = new ArrayList<Role>();
            for (Role role : dataStore.getRoles()) {
                if (isRoleAssignableByUser(role, verifiedUserToken)) {
                    assignableRoles.add(role);
                }
            }

            return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new EditUserView(verifiedUserToken, user, assignableRoles, message)).build();

        } catch (Exception e) {
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }
    }

    @Path("changePassword.html")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response getChangePasswordView(@CookieParam("authUser") String token, @QueryParam("message") String message) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(token);
            if (verifiedUserToken != null) {
                return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(new ChangePasswordView(verifiedUserToken, message)).build();
            } else {
                return Response.seeOther(new URI(LOGIN_HTML.toString() + "?destination=" + URLEncoder.encode(serviceBaseURL + "changePassword.html", "utf8"))).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
        } catch (Exception e) {
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }
    }

    @POST
    @Timed
    @Path("login")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"application/json"})
    public Response login(@CookieParam("authUser") String existingUserCookie, @FormParam("destination") String destination, @FormParam("username") String username, @FormParam("password") String password) {
        try {
            if (!Strings.isNullOrEmpty(username) && !Strings.isNullOrEmpty(password)) {
                UserAccount user = dataStore.getUser(username);
                if (user != null && user.hashedPassword != null && user.hashedPassword.equalsIgnoreCase(UserAccount.hashPassword(password, salt))) {
                    try {
                        //Create a new token for this session
                        String token = UUID.randomUUID().toString();

                        //Save a new UserToken for this session
                        UserToken userToken = new UserToken();
                        userToken.token = token;
                        userToken.userAccount = user;
                        userToken.created = System.currentTimeMillis();
                        userToken = dataStore.newUserToken(userToken);

                        return Response.seeOther(((!Strings.isNullOrEmpty(destination))?new URI(destination):LANDING_HTML)).cacheControl(NO_CACHE_CONTROL).cookie(newUserCookie(userToken.token)).build();
                    } catch(Exception e) {
                        e.printStackTrace();
                        //fall through to fail code
                    }
                }
            }

            //If login fails, log them out just in case were already logged in previously
            logoutUserToken(existingUserCookie);
            return Response.seeOther(new URI(serviceBaseURL + "login.html?" + "destination=" + ((!Strings.isNullOrEmpty(destination))?URLEncoder.encode(destination, "UTF-8"):"") +
                "&message="+URLEncoder.encode("Login unsuccessful", "UTF-8") )).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();

        } catch (Exception e) {
            L.error("Unable to login user: " + username, e);
        }

        throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
    }

    @POST
    @Timed
    @Path("createUser")
    @Consumes("application/x-www-form-urlencoded")
    @Produces(MediaType.TEXT_HTML)
    public Response createUser(@CookieParam("authUser") String existingUserCookie, @FormParam("username") @NotNull String username, @FormParam("password") @NotNull String password, @FormParam("passwordConfirm") @NotNull String passwordConfirm, @FormParam("displayName") @NotNull String displayName, MultivaluedMap<String, String> formParams) {
        try {

            UserToken verifiedUserToken = doVerifyUserToken(existingUserCookie);

            //Make sure they are logged in
            if (verifiedUserToken == null) {
                return Response.seeOther(new URI(LOGIN_HTML.toString() + "?destination=" + URLEncoder.encode(serviceBaseURL + "createUser.html", "utf8"))).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
            //Make sure they have the useradmin role
            if (!verifiedUserToken.userAccount.hasRole("UserAdmin")) {
                return Response.seeOther(PERMISSION_DENIED_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }

            //Validate the incoming parameters

            //Validate userName
            if (Strings.isNullOrEmpty(username)) {
                return Response.seeOther(new URI(serviceBaseURL.toString()+"createUser.html?message=" + URLEncoder.encode("Username is required","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }
            UserAccount alreadyExistingUser = dataStore.getUser(username);
            if (alreadyExistingUser != null) {
                return Response.seeOther(new URI(serviceBaseURL.toString()+"createUser.html?message=" + URLEncoder.encode("Username "+username+" isn't available","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Validate displayName
            if (Strings.isNullOrEmpty(displayName)) {
                return Response.seeOther(new URI(serviceBaseURL.toString()+"createUser.html?message=" + URLEncoder.encode("Display name is required","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Validate password
            if (Strings.isNullOrEmpty(password) || Strings.isNullOrEmpty(passwordConfirm) || !password.equals(passwordConfirm)) {
                return Response.seeOther(new URI(serviceBaseURL.toString()+"createUser.html?message=" + URLEncoder.encode("Passwords don't match","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Update Roles
            List<Integer> newUserRoleIds = new ArrayList<Integer>();
            if (formParams.keySet() != null){
                for (String key : formParams.keySet()){
                    if (key.startsWith("newUserRole_")){
                        newUserRoleIds.add(Integer.parseInt(formParams.get(key).get(0)));
                    }
                }
            }
            List<Role> newUserRoles = new ArrayList<Role>();
            for (Role role : dataStore.getRoles()){
                //Verify that the Roles can be assigned by the logged in UserAccount
                if (isRoleAssignableByUser(role, verifiedUserToken)) {
                    if (newUserRoleIds.contains(role.id)){
                        newUserRoles.add(role);
                    }
                }
            }

            //Create the new user
            UserAccount newUser = new UserAccount();
            newUser.name = username;
            newUser.hashedPassword = UserAccount.hashPassword(password, salt);
            newUser.displayName = displayName;
            newUser.roles = newUserRoles;
            dataStore.createUser(newUser);

            return Response.seeOther(new URI(serviceBaseURL + "manageUsers.html?message=" + URLEncoder.encode("New user " + username + " created successfully", "utf8"))).cacheControl(NO_CACHE_CONTROL).build();
        } catch (Throwable t) {
            L.error("Error creating new user", t);
        }

        throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
    }

    @POST
    @Timed
    @Path("editUser")
    @Consumes("application/x-www-form-urlencoded")
    @Produces(MediaType.TEXT_HTML)
    public Response editUser(@CookieParam("authUser") String existingUserCookie, @FormParam("userName") @NotNull String userName, @FormParam("displayName") @NotNull String displayName, @FormParam("password") @NotNull String password, @FormParam("passwordConfirm") @NotNull String passwordConfirm, MultivaluedMap<String, String> formParams) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(existingUserCookie);

            //Make sure they are logged in
            if (verifiedUserToken == null) {
                return Response.seeOther(new URI(LOGIN_HTML.toString() + "?destination=" + URLEncoder.encode(serviceBaseURL + "editUser.html?userName="+userName, "utf8"))).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }
            //Make sure they have the useradmin role
            if (!verifiedUserToken.userAccount.hasRole("UserAdmin")) {
                return Response.seeOther(PERMISSION_DENIED_HTML).cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build();
            }

            //Validate userName
            if (Strings.isNullOrEmpty(userName)) {
                throw new RuntimeException("userName parameter was null!"); // Can't reload the page without the userName
            }

            //Validate displayName
            if (Strings.isNullOrEmpty(displayName)) {
                return Response.seeOther(new URI(serviceBaseURL+"editUser.html?userName="+URLEncoder.encode(userName,"utf8")+"&message=" + URLEncoder.encode("Display Name is Required", "utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Validate actual user and that logged in user can edit this user
            UserAccount user = dataStore.getUser(userName);
            if (user==null) {
                throw new RuntimeException("Someone tried to edit non-existing user: " + userName);
            }

            //Check passwords and set to new password
            if (!Strings.isNullOrEmpty(password) || !Strings.isNullOrEmpty(passwordConfirm)) {
                if (password!=null && passwordConfirm!=null && password.equals(passwordConfirm)){
                    user.hashedPassword = UserAccount.hashPassword(password, salt);
                } else {
                    return Response.seeOther(new URI(serviceBaseURL+"editUser.html?userName="+URLEncoder.encode(userName,"utf8")+"&message="+ URLEncoder.encode("New passwords don't match", "utf8"))).cacheControl(NO_CACHE_CONTROL).build();
                }
            }

            //Update displayName
            user.displayName = displayName;

            //Update Roles
            List<Integer> newUserRoleIds = new ArrayList<Integer>();
            if (formParams.keySet() != null){
                for (String key : formParams.keySet()){
                    if (key.startsWith("newUserRole_")){
                        newUserRoleIds.add(Integer.parseInt(formParams.get(key).get(0)));
                    }
                }
            }
            List<Role> newUserRoles = new ArrayList<Role>();
            for (Role role : dataStore.getRoles()){
                //Verify that the Roles can be assigned by the logged in UserAccount
                if (isRoleAssignableByUser(role, verifiedUserToken)) {
                    if (newUserRoleIds.contains(role.id)){
                        newUserRoles.add(role);
                    }
                }
            }
            user.roles = newUserRoles;

            //Update user in the DB
            dataStore.updateUser(user);

            return Response.seeOther(new URI(serviceBaseURL+"manageUsers.html?message=" + URLEncoder.encode("Updated user " + userName, "utf8"))).cacheControl(NO_CACHE_CONTROL).build();

        } catch (Exception e) {
            //TODO
            e.printStackTrace();
        }

        throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).entity("Woops, that shouldn't have happened!  Your request was not processed.").build());
    }

    @POST
    @Timed
    @Path("changePassword")
    @Consumes("application/x-www-form-urlencoded")
    @Produces(MediaType.TEXT_HTML)
    public Response changePassword(@CookieParam("authUser") String token, @FormParam("passwordVerify") @NotNull String passwordVerify, @FormParam("password") @NotNull String password, @FormParam("passwordConfirm") @NotNull String passwordConfirm) {
        try {
            UserToken verifiedUserToken = doVerifyUserToken(token);
            //Verify logged in
            if (verifiedUserToken == null) {
                return Response.seeOther(new URI(LOGIN_HTML.toString()+"?destination="+URLEncoder.encode(serviceBaseURL+"changePassword.html","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Verify passwords
            if (Strings.isNullOrEmpty(passwordVerify) ||
                    Strings.isNullOrEmpty(password) ||
                    Strings.isNullOrEmpty(passwordConfirm) ||
                    !verifiedUserToken.userAccount.hashedPassword.equals(UserAccount.hashPassword(passwordVerify, salt)) ||
                    !password.equals(passwordConfirm) ) {
                return Response.seeOther(new URI(serviceBaseURL+"changePassword.html?message="+URLEncoder.encode("Something wasn't right, please try again","utf8"))).cacheControl(NO_CACHE_CONTROL).build();
            }

            //Update user's password
            verifiedUserToken.userAccount.hashedPassword = UserAccount.hashPassword(password, salt);
            dataStore.updateUser(verifiedUserToken.userAccount);

            return Response.seeOther(new URI(LANDING_HTML.toString() + "?message=" + URLEncoder.encode("Your password has been changed", "utf8"))).cacheControl(NO_CACHE_CONTROL).build();
        } catch (Exception e) {
            L.error("Wasn't able to change password", e);
            throw new WebApplicationException(Response.serverError().cacheControl(NO_CACHE_CONTROL).cookie(newEmptyExpiredCookie()).build());
        }
    }

    @GET
    @Timed
    @Path("accountNavDetails")
    @Produces({"application/json"})
    public Response accountNavDetails(@CookieParam("authUser") String token, @HeaderParam("Origin") String origin){
        String errorMessage = null;

        try{
            UserToken verifiedUserToken = doVerifyUserToken(token);
            UserNavDetails details = new UserNavDetails();

            if (verifiedUserToken != null){
                details.setDisplayName(verifiedUserToken.userAccount.displayName);
                details.setLoggedIn(true);
                details.setRoles(verifiedUserToken.userAccount.roles);


            }
            return Response.ok().cacheControl(NO_CACHE_CONTROL).header("Access-Control-Allow-Origin", origin).header("Access-Control-Allow-Credentials", "true").entity(details).build();
        } catch (Exception e) {
            e.printStackTrace();
            errorMessage = "Woops, that shouldn't have happened! Your request was not processed.";
        }
        throw new WebApplicationException(Response.status(401).cacheControl(NO_CACHE_CONTROL).entity(errorMessage).build());

    }


    @POST
    @Timed
    @Path("getUserDetails")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"application/json"})
    public Response verifyUserToken(@HeaderParam("serviceId") @NotNull String serviceToken, @HeaderParam("userSessionId") @NotNull String token) {
        String errorMessage = null;

        try {

            ServiceAccount verifiedService = doVerifyServiceToken(serviceToken);
            if (verifiedService == null) {
                return Response.status(401).cacheControl(NO_CACHE_CONTROL).entity("Calling service is not authorized").build();
            }

            if (!verifiedService.hasRole("VerifyToken")) {
                return Response.status(401).cacheControl(NO_CACHE_CONTROL).entity("Calling service is not authorized").build();
            }

            UserToken verifiedUserToken = doVerifyUserToken(token);
            if (verifiedUserToken != null) {
                UserDetails details = new UserDetails();
                details.setName(verifiedUserToken.userAccount.name);
                details.setDisplayName(verifiedUserToken.userAccount.displayName);
                details.setRoles(new ArrayList<String>());
                for (Role role : verifiedUserToken.userAccount.roles) {
                    details.getRoles().add(role.name);
                }

                return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(details).build();
            }
        } catch (Exception e) {
            L.error("Error verifying userSessionId: " + token, e);
            errorMessage = "An unexpected error occurred";
        }
        throw new WebApplicationException(Response.status(401).cacheControl(NO_CACHE_CONTROL).entity(errorMessage).build());
    }

    @POST
    @Timed
    @Path("getServiceDetails")
    @Consumes("application/x-www-form-urlencoded")
    @Produces({"application/json"})
    public Response verifyServiceToken(@HeaderParam("serviceId") @NotNull String serviceToken, @HeaderParam("callingServiceId") @NotNull String serviceTokenToVerify) {
        String errorMessage = null;

        try {

            //Make sure our direct caller has authservice to call us
            ServiceAccount verifiedService = doVerifyServiceToken(serviceToken);
            if (verifiedService == null) {
                return Response.status(401).cacheControl(NO_CACHE_CONTROL).entity("Calling service is not authorized").build();
            }
            if (!verifiedService.hasRole("VerifyToken")) {
                return Response.status(401).cacheControl(NO_CACHE_CONTROL).entity("Calling service is not authorized").build();
            }


            //Check the service token they are calling about
            ServiceAccount verifiedServiceTokenToVerify = doVerifyServiceToken(serviceTokenToVerify);
            if (verifiedServiceTokenToVerify != null) {
                ServiceDetails details = new ServiceDetails();
                details.setName(verifiedServiceTokenToVerify.name);
                details.setRoles(new ArrayList<String>());
                for (Role role : verifiedServiceTokenToVerify.roles) {
                    details.getRoles().add(role.name);
                }

                return Response.ok().cacheControl(NO_CACHE_CONTROL).entity(details).build();
            }
        } catch (Exception e) {
            L.error("Error verifying callingServiceId: " + serviceTokenToVerify, e);
            e.printStackTrace();
            errorMessage = "An unexpected error occurred";
        }
        throw new WebApplicationException(Response.status(401).cacheControl(NO_CACHE_CONTROL).entity(errorMessage).build());
    }

    private UserToken doVerifyUserToken(String token) {
        if (token == null) {
            return null;
        }
        try {
            UserToken userToken = dataStore.getUserToken(token);
            if (userToken != null && userToken.created != null && userToken.loggedOut == null) {
                //length of validity in millis
                //TODO make the timout configurable, Cookie Timeout must match
                Long validFor = 12L * 60L * 60L * 1000L; // 12 hours
                if (userToken.created > (System.currentTimeMillis()-validFor)) {
                    return userToken;
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return null;
    }

    private ServiceAccount doVerifyServiceToken(String token) {
        if (token == null) {
            return null;
        }
        try {
            return dataStore.getService(token);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Exception Safe
     *
     * @param token
     */
    private void logoutUserToken(String token) {
        try {
            if (token != null) {
                UserToken verifiedUserToken = doVerifyUserToken(token);
                if (verifiedUserToken != null) {
                    verifiedUserToken.loggedOut = System.currentTimeMillis();
                    dataStore.updateUserToken(verifiedUserToken);
                }
            }
        } catch (Exception e) {
            L.error("Unexpected exception occurred while trying to logout a user with token: " + token, e);
        }
    }

    private NewCookie newUserCookie(String userToken) {
        return new NewCookie("authUser", userToken, "/", ((cookieDomainName !=null)? cookieDomainName :null), null, 12*60*60, cookieSecureOnly); // 12 hours
    }

    private NewCookie newEmptyExpiredCookie() {
        return new NewCookie("authUser", null, "/", ((cookieDomainName !=null)? cookieDomainName :null), null, 0, cookieSecureOnly);
    }

    private static boolean isRoleAssignableByUser(Role role, UserToken verifiedUserToken) {
        try {
            if (role == null || role.assignableBy == null || role.assignableBy.length()<3 || verifiedUserToken == null) {
                throw new RuntimeException();
            }
            UserAccount user = verifiedUserToken.userAccount;
            String[] assigners = role.assignableBy.split(",");
            for (String assignerRole : assigners) {
                assignerRole = assignerRole.trim();
                if (user.hasRole(assignerRole)) {
                    return true;
                }
            }
        } catch (Throwable t) {
            //fall through
        }
        return false;
    }

}
