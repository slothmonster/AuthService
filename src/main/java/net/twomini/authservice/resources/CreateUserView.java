package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;
import net.twomini.authservice.data.Role;
import net.twomini.authservice.data.UserToken;

import java.util.List;

public class CreateUserView extends View {

    public UserToken verifiedUserToken;
    public List<Role> assignableRoles;
    public String message;

    public boolean hasRoleUserAdmin = false;

    public CreateUserView(UserToken verifiedUserToken, List<Role> assignableRoles, String message) {
        super("createUser.mustache");
        this.verifiedUserToken = verifiedUserToken;
        this.assignableRoles = assignableRoles;
        this.message = message;
        hasRoleUserAdmin = verifiedUserToken.userAccount.hasRole("UserAdmin");
    }

}