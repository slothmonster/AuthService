package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;
import net.twomini.authservice.data.UserAccount;
import net.twomini.authservice.data.UserToken;

import java.util.List;

public class ManageUserView extends View {

    public UserToken verifiedUserToken;
    public String message;
    public List<UserAccount> userList;

    public boolean hasRoleUserAdmin = false;

    public ManageUserView(UserToken verifiedUserToken, List<UserAccount> availableUsers, String message) {
        super("manageUser.mustache");
        this.verifiedUserToken = verifiedUserToken;
        this.message = message;
        this.userList = availableUsers;

        hasRoleUserAdmin = verifiedUserToken.userAccount.hasRole("UserAdmin");
    }

}