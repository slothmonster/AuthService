package net.twomini.authservice.data;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class InMemoryDataStore implements DataStore {

    AtomicInteger roleIdGenerator = new AtomicInteger(0);
    AtomicInteger userAccountIdGenerator = new AtomicInteger(0);
    AtomicInteger serviceAccountIdGenerator = new AtomicInteger(0);
    AtomicInteger userTokenIdGenerator = new AtomicInteger(0);

    List<Role> roles = new ArrayList<Role>();
    List<UserAccount> users = new ArrayList<UserAccount>();
    List<ServiceAccount> services = new ArrayList<ServiceAccount>();
    List<UserToken> userTokens = new ArrayList<UserToken>();

    private String salt;

    public InMemoryDataStore(String salt) {
        this.salt = salt;

        Role userAdminRole = new Role(roleIdGenerator.incrementAndGet(), "UserAdmin", "UserAdmin");
        Role developerRole = new Role(roleIdGenerator.incrementAndGet(), "Developer", "UserAdmin");

        roles.add(userAdminRole);

        users.add(new UserAccount(userAccountIdGenerator.incrementAndGet(), "boss", "Pointy Hair Boss", UserAccount.hashPassword("boss", salt), Arrays.asList(new Role[]{userAdminRole})));
        users.add(new UserAccount(userAccountIdGenerator.incrementAndGet(), "wally", "Wally", UserAccount.hashPassword("wally", salt), Arrays.asList(new Role[]{developerRole})));

        services.add(new ServiceAccount(serviceAccountIdGenerator.incrementAndGet(), "testServiceAccount", "4bc1b91b-39d6-4b9f-a8e0-bdcb29e6bdf1a608e3a1-8ecf-4583-8ce1-00c9e410cb54", Arrays.asList(new Role[]{developerRole})));
    }

    @Override
    public List<Role> getRoles() {
        return roles;
    }

    @Override
    public List<UserAccount> getUsers() {
        Collections.sort(users);
        return users;
    }

    @Override
    public UserAccount getUser(String name) {
        for (UserAccount user : users) {
            if (user.name.equalsIgnoreCase(name)) {
                return user;
            }
        }
        return null;
    }

    @Override
    public UserToken newUserToken(UserToken newUserToken) {
        newUserToken.id = userTokenIdGenerator.incrementAndGet();
        userTokens.add(newUserToken);
        return newUserToken;
    }

    @Override
    public UserAccount createUser(UserAccount newUserAccount) {
        newUserAccount.id = userAccountIdGenerator.incrementAndGet();
        users.add(newUserAccount);
        return newUserAccount;
    }

    @Override
    public void updateUser(UserAccount updatedUser) {
        for (UserAccount user : users) {
            if (updatedUser.id.equals(user.id)) {
                users.remove(user);
                users.add(updatedUser);
                break; // Modifying the list we iterating over, must break out of the for loop now!
            }
        }
    }

    @Override
    public UserToken getUserToken(String token) {
        for (UserToken userToken : userTokens) {
            if (userToken.token.equals(token)) {
                for (UserAccount user : users) {
                    if (userToken.userAccount.id.equals(user.id)) {
                        userToken.userAccount = user;
                        return userToken;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public ServiceAccount getService(String token) {
        for (ServiceAccount service : services) {
            if (service.token.equals(token)) {
                return service;
            }
        }
        return null;
    }

    @Override
    public void updateUserToken(UserToken updatedUserToken) {
        for (UserToken userToken : userTokens) {
            if (userToken.token.equals(updatedUserToken.token)) {
                userTokens.remove(userToken);
                userTokens.add(updatedUserToken);
                break; // Modifying the list we iterating over, must break out of the for loop now!
            }
        }
    }

}
