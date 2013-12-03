package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;
import net.twomini.authservice.data.UserToken;

public class ChangePasswordView extends View {

    public UserToken verifiedUserToken;
    public String message;

    public boolean hasRoleUserAdmin = false;

    public ChangePasswordView(UserToken verifiedUserToken, String message) {
        super("changePassword.mustache");
        this.verifiedUserToken = verifiedUserToken;
        this.message = message;

        hasRoleUserAdmin = verifiedUserToken.userAccount.hasRole("UserAdmin");
    }

}
