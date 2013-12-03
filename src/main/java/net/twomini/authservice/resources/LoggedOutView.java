package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;

public class LoggedOutView extends View {

    public LoggedOutView() {
        super("loggedOut.mustache");
    }

}