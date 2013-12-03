package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;
import net.twomini.authservice.data.UserToken;

public class PermissionDeniedView extends View {

    public UserToken verifiedUserToken;

    public PermissionDeniedView(UserToken verifiedUserToken) {
        super("permissionDenied.mustache");
        this.verifiedUserToken = verifiedUserToken;
    }

}