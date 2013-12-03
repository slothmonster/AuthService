package net.twomini.authservice.data;

import java.util.List;

public class ServiceAccount {

    public Integer id;

    public String name;

    public String token;

    public List<Role> roles;

    public ServiceAccount(Integer id, String name, String token, List<Role> roles) {
        this.id = id;
        this.name = name;
        this.token = token;
        this.roles = roles;
    }

    public boolean hasRole(String role) {
        if (role != null && roles != null) {
            for (Role r : roles) {
                if (r != null && r.name != null && r.name.toLowerCase().equalsIgnoreCase(role.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

}
