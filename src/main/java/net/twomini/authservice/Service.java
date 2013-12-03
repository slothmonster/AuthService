package net.twomini.authservice;

import com.yammer.dropwizard.assets.AssetsBundle;
import net.twomini.authservice.data.DataStore;
import net.twomini.authservice.data.InMemoryDataStore;
import net.twomini.authservice.health.DefaultHealthCheck;
import net.twomini.authservice.resources.AuthResource;
import com.yammer.dropwizard.config.Bootstrap;
import com.yammer.dropwizard.config.Environment;
import com.yammer.dropwizard.views.ViewBundle;

public class Service extends com.yammer.dropwizard.Service<AuthConfiguration> {

    private String serviceName;

    public static void main(String[] args) throws Exception {
        new Service().run(args);
    }

    @Override
    public void initialize(Bootstrap<AuthConfiguration> bootstrap) {
        bootstrap.setName("AuthService");
        bootstrap.addBundle(new ViewBundle());
        bootstrap.addBundle(new AssetsBundle("/assets/", "/assets"));
    }

    @Override
    public void run(AuthConfiguration configuration, Environment environment) {
        this.serviceName = configuration.getServiceName();

        DataStore dataStore = new InMemoryDataStore(configuration.getSalt());
        environment.addResource(new AuthResource(dataStore,
                configuration.getCookieDomainName(), configuration.getCookieSecureOnly(),
                configuration.getServiceBaseURL(),
                configuration.getSalt()));


        environment.addHealthCheck(new DefaultHealthCheck());

    }

}