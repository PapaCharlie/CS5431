<#include "vault.ftl">

<#macro page_head>
<#--<script type="text/javascript" src="/userlog.js"></script>-->
</#macro>

<#macro page_body>
<div class="container col-sm-9 col-md-10">
    <ul class="nav nav-tabs">
        <li role="presentation" class="active"><a href="#sessions" data-toggle="tab">Sessions</a></li>
        <li role="presentation"><a href="#master" data-toggle="tab">Master Password</a></li>
    </ul>
    <div class="tab-content">
        <div class="tab-pane active in" style="padding: 5px;" id="sessions">
            <form action="/settings" method="post" id="settingsForm">
                <div class="form-group">
                    <label for="phoneNumber" class="control-label">Phone number: </label>
                    <input style="width: 200px;" type="tel" min="1" max="20" name="phoneNumber"
                           id="phoneNumber" pattern="^\d{3}-\d{3}-\d{4}$"
                           class="form-control" required value="${phoneNumber!5}">
                </div>
                <div class="form-group">
                    <label for="concurrentSessions" class="control-label">Maximum number of concurrent users: </label>
                    <input style="width: 100px;" type="number" min="1" max="20" name="concurrentSessions"
                           id="concurrentSessions"
                           class="form-control" required value="${concurrentSessions!5}">
                </div>
                <div class="form-group">
                    <label for="sessionLength" class="control-label">Maximum session length: </label>
                    <input style="width: 100px;" type="number" min="2" max="1440" name="sessionLength"
                           id="sessionLength"
                           class="form-control" required value="${sessionLength!60}">
                </div>
                <button class="btn btn-success" type="submit">Save</button>
            </form>
        </div>
        <div class="tab-pane" style="padding: 5px;" id="master">
            <h4>Change Your Master Password <h4 style="color: red;">This is IMPORTANT- DO NOT FORGET IT</h4></h4>
            <form action="/changepassword" method="post" id="changePasswordForm">
                <div class="form-group">
                    <label for="oldPassword" class="control-label">Current password: </label>
                    <input style="width:50%" type="password" name="oldPassword" id="oldPassword" class="form-control"
                           required>
                </div>
                <div class="form-group">
                    <label for="newPassword1" class="control-label">New password: </label>
                    <input style="width:50%" type="password" name="newPassword1" id="newPassword1" class="form-control"
                           required>
                </div>
                <div class="form-group">
                    <label for="newPassword2" class="control-label">Confirm new password: </label>
                    <input style="width:50%" type="password" name="newPassword2" id="newPassword2" class="form-control"
                           required>
                </div>
                <button class="btn btn-success" type="submit">Save</button>
            </form>
        </div>
    </div>
</div>
<script>
    $("#settingsForm").on('submit', function (event) {
        event.preventDefault();
        var values = {};
        $(this).find(':input').each(function () {
            if (this.name) {
                values[this.name] = this.value;
            }
        });
        $.post('/settings', values, function (data) {
            var response = JSON.parse(data);
            if (response.success) {
                window.location = "/settings";
            } else {
                alert(response.error);
            }
        });
    });

    $("#changePasswordForm").on('submit', function (event) {
        event.preventDefault();
        if (sessionStorage.getItem("password")) {
            $.get("/passwords", function (payload) {
                var masterKey;
                var passwords;
                var data = JSON.parse(payload);
                if (data
                        && data.hasOwnProperty("passwords")
                        && data.hasOwnProperty("salt")
                        && data.hasOwnProperty("privateEncryptionKey")
                        && data.hasOwnProperty("privateSigningKey")) {
                    var masterPassword = fromB64(sessionStorage.getItem("password"));
                    masterKey = deriveMasterKey(data.salt, masterPassword);
                    passwords = decryptPasswords(masterKey, data.passwords);

                    $oldPassword = $("#oldPassword");
                    $newPassword1 = $("#newPassword1");
                    $newPassword2 = $("#newPassword2");

                    var newHashedPassword = hash($newPassword1.val());
                    var newKey = deriveMasterKey(data.salt, newHashedPassword);

                    var reEncryptedPasswords;
                    if (passwords.length > 0) {
                        reEncryptedPasswords = passwords.map(function (password) {
                            var newPassword = {};
                            newPassword.name = encrypt(newKey, password.name);
                            newPassword.url = encrypt(newKey, password.url);
                            newPassword.username = encrypt(newKey, password.username);
                            newPassword.password = encrypt(newKey, password.password);
                            newPassword.id = password.id;
                            return newPassword;
                        });
                    } else {
                        reEncryptedPasswords = [];
                    }

                    var newPrivateEncryptionKey = serializePrivateKey(newHashedPassword, parseElGamalPrivateKey(masterPassword, data.privateEncryptionKey));
                    var newPrivateSigningKey = serializePrivateKey(newHashedPassword, parseECDSAPrivateKey(masterPassword, data.privateSigningKey));

                    $.post("/changepassword", {
                        oldPassword: toB64(hash("auth" + $oldPassword.val())),
                        newPassword1: toB64(hash("auth" + $newPassword1.val())),
                        newPassword2: toB64(hash("auth" + $newPassword2.val())),
                        reEncryptedPasswords: JSON.stringify(reEncryptedPasswords),
                        newPrivateEncryptionKey: newPrivateEncryptionKey,
                        newPrivateSigningKey: newPrivateSigningKey
                    }, function (data) {
                        var response = JSON.parse(data);
                        if (response.success) {
                            sessionStorage.setItem("password", toB64(newHashedPassword));
                            $oldPassword.val("");
                            $newPassword1.val("");
                            $newPassword2.val("");
                            alert("Master password succesfully changed!");
                        } else {
                            alert(response.error);
                        }
                    });

                } else {
                    console.log("Bad payload");
                }
            });
        } else {
            document.cookie = "token=;expires=Thu, 01 Jan 1970 00:00:01 GMT;";
            window.location = "/";
        }
    });
</script>
</#macro>

<@display_page/>