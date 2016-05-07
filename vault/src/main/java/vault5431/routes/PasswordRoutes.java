package vault5431.routes;

import org.json.JSONException;
import org.json.JSONObject;
import spark.ModelAndView;
import vault5431.users.Password;

import java.util.HashMap;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Contains routes for displaying users' vaults.
 *
 * @author papacharlie
 */
final class PasswordRoutes extends Routes {

    protected void routes() {

        authenticatedGet("/home", (req, res, token) ->
                new ModelAndView(new HashMap<>(0), "home.ftl")
        );

        authenticatedGet("/passwords", (req, res, token) -> {
            JSONObject vault = new JSONObject();
            vault.put("salt", token.getUser().loadVaultSalt(token).toString());
            Set<Password> passwords = token.getUser().loadPasswords(token);
            vault.put("passwords", passwords.stream().map(Password::toJSONObject).collect(Collectors.toList()));
            vault.put("privateEncryptionKey", token.getUser().loadPrivateEncryptionKey(token));
            vault.put("privateSigningKey", token.getUser().loadPrivateSigningKey(token));
            return vault;
        });

        authenticatedDelete("/passwords/:id", (req, res, token) -> {
            String id = req.params(":id");
            if (!provided(id)) {
                return allFieldsRequired();
            }
            UUID uuid;
            try {
                uuid = UUID.fromString(id);
            } catch (IllegalArgumentException err) {
                return invalidRequest();
            }
            token.getUser().deletePassword(uuid, token);
            return success();
        });

        authenticatedPut("/passwords/:id", (req, res, token) -> {
            UUID uuid;
            String id = req.params(":id");
            String changedPassword = req.queryParams("changedPassword");
            if (!provided(id, changedPassword)) {
                return allFieldsRequired();
            }
            try {
                uuid = UUID.fromString(id);
            } catch (IllegalArgumentException err) {
                return failure(err);
            }
            try {
                JSONObject pass = new JSONObject(changedPassword);
                pass.put("id", uuid.toString());
                token.getUser().changePassword(Password.fromJSON(pass), token);
                return success();
            } catch (JSONException err) {
                return failure(err);
            }
        });

        authenticatedPost("/passwords", (req, res, token) -> {
            String password = req.queryParams("newPassword");
            if (!provided(password)) {
                return allFieldsRequired();
            }
            try {
                JSONObject pass = new JSONObject(password);
                pass.put("id", UUID.randomUUID().toString());
                Password newPassword = Password.fromJSON(pass);
                token.getUser().savePassword(newPassword, token);
            } catch (JSONException err) {
                return failure(err);
            } catch (IllegalArgumentException err) {
                return failure(err);
            }
            return success();
        });

        authenticatedGet("/generator", (req, res, token) ->
                new ModelAndView(new HashMap<>(0), "generator.ftl")
        );

    }

}
