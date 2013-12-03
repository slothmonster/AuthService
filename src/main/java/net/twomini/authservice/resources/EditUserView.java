package net.twomini.authservice.resources;

import net.twomini.authservice.data.Role;
import net.twomini.authservice.data.UserAccount;
import com.yammer.dropwizard.views.View;
import net.twomini.authservice.data.UserToken;

import java.util.ArrayList;
import java.util.List;

public class EditUserView extends View {

    public UserToken verifiedUserToken;
    public String message;
    public UserAccount userAccount;
    public List<HasRole> hasRoles = new ArrayList<HasRole>();

    public boolean hasRoleUserAdmin = false;

    public EditUserView(UserToken verifiedUserToken, UserAccount user, List<Role> assignableRoles, String message) {
        super("editUser.mustache");
        this.verifiedUserToken = verifiedUserToken;
        this.message = message;
        this.userAccount = user;

        hasRoleUserAdmin = verifiedUserToken.userAccount.hasRole("UserAdmin");

        for (Role role : assignableRoles) {
            boolean hasIt = user.roles.contains(role);
            hasRoles.add(new HasRole(role, hasIt));
        }

    }

    private static class HasRole {
        public Role role;
        public Boolean hasRole = false;

        public HasRole(Role role, Boolean hasRole) {
            this.role = role;
            this.hasRole = hasRole;
        }

    }

}
