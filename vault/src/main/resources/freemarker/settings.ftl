<#include "vault.ftl">

<#macro page_head>
<#--<script type="text/javascript" src="/userlog.js"></script>-->
<script type="text/javascript">
    var wordlist = [];
</script>
<script type="text/javascript" src="/10k.js"></script>
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
                <div class="strength" id="length" style="color:#FF0000;display:none"> Password is not strong! Short
                    passwords are easy to guess. Try one with at least 8 characters.
                </div>
                <div class="strength" id="uppercase" style="color:#FF0000;display:none"> Password is not strong! Try
                    including an uppercase letter.
                </div>
                <div class="strength" id="lowercase" style="color:#FF0000;display:none"> Password is not strong!Try
                    including a lowercase letter.
                </div>
                <div class="strength" id="wordlist" style="color:#FF0000;display:none"> Password is not strong! Try one
                    without common words or passwords.
                </div>
                <div class="strength" id="digit" style="color:#FF0000;display:none"> Password is not strong! Try including a
                    number.
                </div>
                <div class="strength" id="symbol" style="color:#FF0000;display:none"> Password is not strong! Try including
                    a non-alphanumeric character.
                </div>
                <div class="strength" id="empty" style="color:#FF0000;display:none"> You can't leave this field empty.</div>
                <div class="form-group">
                    <label for="newPassword2" class="control-label">Confirm new password: </label>
                    <input style="width:50%" type="password" name="newPassword2" id="newPassword2" class="form-control"
                           required>
                </div>
                <div id="alert" style="color:#FF0000;display:none" role="alert"> These passwords don't match</div>
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
        var newPassword1 = $('#newPassword1').val();
        var newPassword2 = $('#newPassword2').val();
        var result = is_comprehensive8(newPassword1);
        if (newPassword1 != newPassword2) {
            console.log("SUBMIT FAIL");
            $('#newPassword2').css('border-color', 'red');
            $('#alert').show();
            return false;
        }
        if(!is_basic16(password) && !result[0] ){
            var alert = result[1];
            $('#newPassword1').css('border-color', 'red');
            $(alert).show();
            return false;
        }
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

    $('#newPassword1').on('input', function () {
        $('#newPassword2').val("");
        $('#newPassword2').css('border-color', '#ccc');
        $('#alert').hide();
    });


    $('#newPassword2').focus(function () {
        $('#newPassword2').css('border-color', '#ccc');
        $('#alert').hide();
    });


    $('#newPassword2').blur(function () {
        var password = $('#newPassword1').val();
        var confirm = $('#newPassword2').val();
        console.log(password);
        if (password != confirm) {
            $('#newPassword2').css('border-color', 'red');
            $('#alert').show();
        }

    });

    //checks if password is at least 16 characters long
    function is_basic16(password) {
        if (password.length >= 16) {
            return true;
        }
        else {
            return false;
        }
    }

    function found_in_wordlist(password) {
        var alpha_only = password.replace(/[^a-zA-Z]/g, '').toLowerCase();
        console.log(alpha_only);
        for (var i = 0; i < wordlist.length; i++) {
            if (alpha_only == wordlist[i]) {
                console.log("FOUND");
                console.log(wordlist[i]);
                return true;
            }
        }
        return false;
    }

    //according to Kelly's paper where he defines the comprehensive8 criteria
    //returns an array containing a boolean or the condition it fails
    function is_comprehensive8(password) {
        var result = []
        var check_length = password.length >= 8;
        var has_digit = (/^(?=.*\d)/).test(password);
        var has_capital = (/^(?=.*[A-Z])/).test(password);
        var has_symbol = (/^(?=.*[^a-zA-Z\d])/).test(password);
        var has_lowercase = (/^(?=.*[a-z])/).test(password);
        var patt = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z\d])/;
        var passes_criteria = patt.test(password) && check_length && (!found_in_wordlist(password));
        result.push(passes_criteria);
        if (!check_length) {
            result.push("length");
        }
        else if (!has_digit) {
            result.push("digit");
        }
        else if (!has_capital) {
            result.push("uppercase");
        }
        else if (!has_symbol) {
            result.push("symbol");
        }
        else if (!has_lowercase) {
            result.push("lowercase");
        }
        else if (!passes_criteria) {
            result.push("wordlist");
        }
        else {
            result.push("strong");
        }
        //console.log(wordlist[10]);
        return result;
    }


    $('#newPassword1').blur(function () {
        var password = $('#newPassword1').val();
        var confirm = $('#newPassword2').val();
        //console.log(wordlist[10]);
        if (password == "") {
            $('#empty').show();
            return false;
        }
        if (!(is_basic16(password))) {
            var result = is_comprehensive8(password);
            var error = result[1];
            //console.log(result[0]);
            //console.log(error);
            if (!result[0]) {
                //console.log("error");
                if (error == "length") {
                    $('#newPassword1').css('border-color', 'red');
                    $('#length').show();
                }
                else if (error == "digit") {
                    $('#newPassword1').css('border-color', 'red');
                    $('#digit').show();
                }
                else if (error == "uppercase") {
                    $('#newPassword1').css('border-color', 'red');
                    $('#uppercase').show();
                }
                else if (error == "symbol") {
                    $('#newPassword1').css('border-color', 'red');
                    $('#symbol').show();
                }
                else if (error == "lowercase") {
                    $('#newPassword1').css('border-color', 'red');
                    $('#lowercase').show();
                }
                else {
                    $('#newPassword1').css('border-color', 'red');
                    $('#wordlist').show();
                }

            } else {
                $('#newPassword1').css('border-color', '#ccc');
                $('.strength').hide();
            }

        }
    });


    $('#newPassword1').focus(function () {
        $('#newPassword1').css('border-color', '#ccc');
        $('.strength').hide();
    });
    
</script>
</#macro>

<@display_page/>