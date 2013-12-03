package net.twomini.authservice.data;

public class Role {

    public Integer id;

    public String name;

    public String assignableBy;

    protected Role(Integer id, String name, String assignableBy) {
        this.id = id;
        this.name = name;
        this.assignableBy = assignableBy;
    }
}
