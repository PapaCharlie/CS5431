package vault5431.users.exceptions;

import vault5431.Password;

import java.util.List;

/**
 * Created by papacharlie on 4/7/16.
 */
public class CorruptedVaultException extends Exception {

    private Password[] recoveredPasswords;

    public CorruptedVaultException(Password[] recoveredPasswords) {
        super();
        this.recoveredPasswords = recoveredPasswords;
    }

}
