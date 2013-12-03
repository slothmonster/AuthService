package net.twomini.authservice;

import com.yammer.dropwizard.config.Configuration;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.NotEmpty;

public class AuthConfiguration extends Configuration {

    @NotEmpty
    @JsonProperty
    private String serviceName;

    @NotEmpty
    @JsonProperty
    private String cookieDomainName;

    @JsonProperty
    private boolean cookieSecureOnly;

    @NotEmpty
    @JsonProperty
    private String serviceBaseURL;

    @NotEmpty
    @JsonProperty
    private String salt;

    public String getServiceName() {
        return serviceName;
    }

    public String getCookieDomainName() {
        return cookieDomainName;
    }

    public String getServiceBaseURL() {
        return serviceBaseURL;
    }

    public boolean getCookieSecureOnly() {
        return cookieSecureOnly;
    }

    public String getSalt() {
        return salt;
    }

}