package net.twomini.authservice.health;

import com.yammer.metrics.core.HealthCheck;

public class DefaultHealthCheck extends HealthCheck {

    public DefaultHealthCheck() {
        super("empty-test");
    }

    @Override
    protected Result check() throws Exception {
        if (false) {
            return Result.unhealthy("How did this happen?");
        }
        return Result.healthy();
    }
}