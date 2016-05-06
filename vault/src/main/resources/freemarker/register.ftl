<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vault5431</title>
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>
    <script type="text/javascript" src="/crypto.js"></script>
    <script type="text/javascript">
        var wordlist = [];
    </script>
    <script type="text/javascript" src="/10k.js"></script>

<body>
<div class="login" id="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Sign up </h2>
    <div class="login-container">
        <form action="/register" method="post" id="signupForm">
            <label for="usernamesignup" class="uname" data-icon="u">Your Username</label>
            <p><input type="text" name="username" placeholder="Username" pattern="\w+" maxlength="40" required autofocus></p>
            <label for="passwordsignup">Your Password </label>
            <p><input type="password" name="password" id="password" placeholder="Password" required></p>
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
            <label for="paswordsignup">Your Password (confirm) </label>
            <p><input type="password" id="confirm" name="confirm" class="form-error" placeholder="Password" required>
            </p>
            <div id="alert" style="color:#FF0000;display:none" role="alert"> These passwords don't match</div>
            <label for="phonesignup">Your Phone Number (of form: 123-456-7890) </label>
            <p><input type="tel" name="phoneNumber" placeholder="Phone Number" pattern="^\d{3}-\d{3}-\d{4}$" required>
            </p>
            <input type="hidden" name="pubCryptoKey" id="pubCryptoKey">
            <input type="hidden" name="privCryptoKey" id="privCryptoKey">
            <input type="hidden" name="pubSigningKey" id="pubSigningKey">
            <input type="hidden" name="privSigningKey" id="privSigningKey">
            <p><input type="submit" id="submit" value="Sign Up"></p>
        </form>
        <p>
            Already a Member? <a href="/" class="to_register">Log In!</a>
        </p>
    <#if error??>
        <p class="has-error">${error}</p>
    </#if>
    </div>
</div>
<script>
    $(document).ready(function () {
        sessionStorage.removeItem("password");
        $("#signupForm").submit(function (event) {
            var passwordField = $(this).find("#password");
            var confirmField = $(this).find("#confirm");

            var password = passwordField.val();
            var confirm = confirmField.val();
            var result = is_comprehensive8(password);
            if (password != confirm) {
                confirmField.css('border-color', 'red');
                $('#alert').show();
                return false;
            }else if((!is_basic16(password) && !result[0])){
                    var alert = result[1];
                    passwordField.css('border-color', 'red');
                    $(alert).show();
                    return false;
            } else {
                var key = hash(passwordField.val());

                passwordField.val(toB64(hash("auth" + passwordField.val())));
                confirmField.val(toB64(hash("auth" + confirmField.val())));

                var cryptoPair = generateElGamalKeys();
                var pubCryptoKey = serializePublicKey(cryptoPair.pub);
                var privCryptoKey = serializePrivateKey(key, cryptoPair.sec);

                var signingPair = generateECDSAKeys();
                var pubSigningKey = serializePublicKey(signingPair.pub);
                var privSigningKey = serializePrivateKey(key, signingPair.sec);

                var pubCryptoKeyField = $(this).find("#pubCryptoKey");
                var privCryptoKeyField = $(this).find("#privCryptoKey");
                var pubSigningKeyField = $(this).find("#pubSigningKey");
                var privSigningKeyField = $(this).find("#privSigningKey");

                pubCryptoKeyField.val(pubCryptoKey);
                privCryptoKeyField.val(privCryptoKey);
                pubSigningKeyField.val(pubSigningKey);
                privSigningKeyField.val(privSigningKey);

            }
        });
    });

    $('#password').on('input', function () {
        $('#confirm').val("");
        $('#confirm').css('border-color', '#888');
        $('#alert').hide();
    });


    $('#confirm').focus(function () {
        $('#confirm').css('border-color', '#888');
        $('#alert').hide();
    });


    $('#confirm').blur(function () {
        var password = $('#password').val();
        var confirm = $('#confirm').val();
        if (password != confirm) {
            $('#confirm').css('border-color', 'red');
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
        for (var i = 0; i < wordlist.length; i++) {
            if (alpha_only == wordlist[i]) {
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


    $('#password').blur(function () {
        var password = $('#password').val();
        var confirm = $('#confirm').val();
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
                    $('#password').css('border-color', 'red');
                    $('#length').show();
                }
                else if (error == "digit") {
                    $('#password').css('border-color', 'red');
                    $('#digit').show();
                }
                else if (error == "uppercase") {
                    $('#password').css('border-color', 'red');
                    $('#uppercase').show();
                }
                else if (error == "symbol") {
                    $('#password').css('border-color', 'red');
                    $('#symbol').show();
                }
                else if (error == "lowercase") {
                    $('#password').css('border-color', 'red');
                    $('#lowercase').show();
                }
                else {
                    $('#password').css('border-color', 'red');
                    $('#wordlist').show();
                }

            } else {
                $('#password').css('border-color', '#888');
                $('.strength').hide();
            }

        }
    });


    $('#password').focus(function () {
        $('#password').css('border-color', '#888');
        $('.strength').hide();
    });

</script>
</body>
</html>
