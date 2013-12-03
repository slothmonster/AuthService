package net.twomini.authservice.resources;

import com.yammer.dropwizard.views.View;

public class LoginView extends View {

    public String destination;
    public String message;

    public LoginView(String destination, String message) {
        super("login.mustache");
        this.destination = destination;
        this.message = message;
    }

}