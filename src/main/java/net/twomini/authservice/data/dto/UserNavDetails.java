package net.twomini.authservice.data.dto;

import net.twomini.authservice.data.Role;

import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: ardeibert
 * Date: 12/3/13
 * Time: 6:46 PM
 * To change this template use File | Settings | File Templates.
 */
public class UserNavDetails {

    private boolean isLoggedIn = false;

    private String displayName = null;

    private List<Role> roles = null;

    public boolean isLoggedIn() {
        return isLoggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        isLoggedIn = loggedIn;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }
}
