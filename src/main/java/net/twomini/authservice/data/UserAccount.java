package net.twomini.authservice.data;

import java.security.MessageDigest;
import java.util.List;

public class UserAccount implements Comparable<UserAccount> {

    public Integer id;

    public String name;

    public String displayName;

    public String hashedPassword;

    public List<Role> roles;


    public UserAccount() {
    }

    public UserAccount(Integer id, String name, String displayName, String hashedPassword, List<Role> roles) {
        this.id = id;
        this.name = name;
        this.displayName = displayName;
        this.hashedPassword = hashedPassword;
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

    public static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((password + salt).getBytes());
            byte byteData[] = md.digest();
            //convert the byte to hex format method 1
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean equals(Object o) {
        return o!=null && o instanceof UserAccount && ((UserAccount)o).id!=null && ((UserAccount)o).id.equals(id) && ((UserAccount)o).name!=null && ((UserAccount)o).name.equals(name);
    }

    @Override
    public int compareTo(UserAccount userAccount) {
        if (userAccount == null || userAccount.displayName == null) {
            return 1;
        }
        if (displayName == null) {
            return -1;
        }
        return displayName.compareTo(userAccount.displayName);
    }

}
