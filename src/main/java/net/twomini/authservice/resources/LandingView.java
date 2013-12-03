package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;
import net.twomini.authservice.data.UserToken;

public class LandingView extends View {

    public UserToken verifiedUserToken;

    public String message;

    public boolean hasRoleUserAdmin = false;

    public LandingView(UserToken verifiedUserToken, String message) {
        super("landing.mustache");
        this.verifiedUserToken = verifiedUserToken;
        this.message = message;
        hasRoleUserAdmin = verifiedUserToken.userAccount.hasRole("UserAdmin");
    }

}