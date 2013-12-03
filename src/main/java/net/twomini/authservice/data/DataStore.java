package net.twomini.authservice.data;

import java.util.List;

public interface DataStore {

    public List<Role> getRoles();

    public List<UserAccount> getUsers();

    public UserAccount getUser(String name);

    public UserToken newUserToken(UserToken newUserToken);

    public UserAccount createUser(UserAccount userAccount);

    public void updateUser(UserAccount user);

    public UserToken getUserToken(String token);

    public ServiceAccount getService(String token);

    public void updateUserToken(UserToken updatedUserToken);

}
