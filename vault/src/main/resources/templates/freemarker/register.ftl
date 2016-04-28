<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vault5431</title>
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>
    <script type="text/javascript" src="/crypto.js"></script>
<body>
<div class="login" id="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Sign up </h2>
    <form action="/register" method="post" id="signupForm" class="login-container">
        <label for="usernamesignup" class="uname" data-icon="u">Your Username</label>
        <p><input type="text" name="username" placeholder="Username" required></p>
        <label for="passwordsignup">Your Password </label>
        <p><input type="password" name="password" id="password" placeholder="Password" required></p>
        <div id="strength" style="color:#FF0000;display:none"> Password is not strong </div>
        <label for="paswordsignup">Your Password (confirm) </label>
        <p><input type="password" id="confirm" name="confirm" class= "form-error" placeholder="Password" required></p>
        <div id="alert" style="color:#FF0000;display:none" role="alert"> These passwords don't match </div>
        <label for="phonesignup">Your Phone Number (of form: 123-456-7890) </label>
        <p><input type="tel" name="phoneNumber" placeholder="Phone Number" pattern="^\d{3}-\d{3}-\d{4}$" required></p>
        <p><input type="submit" id="submit" value="Sign Up"></p>
        <p>
            Already a Member? <a href="/" class="to_register">Log In!</a>
        </p>
    <#if error??>
        <p class="has-error">${error}</p>
    </#if>
    </form>
</div>
<script>
    $(document).ready(function () {
        sessionStorage.removeItem("password");
        $("#signupForm").submit(function (event) {
            $passwordField = $('#password');
            var hashedPassword = sjcl.hash.sha256.hash(sjcl.codec.utf8String.toBits($passwordField.val()));
            var hash = sjcl.hash.sha256.hash(hashedPassword);
            $passwordField.val(sjcl.codec.base64url.fromBits(hash));
        });
    });
    $('#password').on('input', function(){
        $('#confirm').val("");
        $('#confirm').css('border-color', '#888');
        $('#alert').hide();
    });



    $('#confirm').focus(function(){
        $('#confirm').css('border-color', '#888');
        $('#alert').hide();
    });


    $('#confirm').blur(function(){
        var password = $('#password').val();
        var confirm = $('#confirm').val();
        console.log(password);
        if(password != confirm){
            $('#confirm').css('border-color', 'red');
            $('#alert').show();
            
        }
    });

    //checks if password is at least 16 characters long
    function is_basic16(password){
        if(password.length >= 16){
            return true;
        }
        else{
            return false;
        }
    }

    //according to Kelly's paper where he defines the comprehensive8 criteria
    function is_comprehensive8(password){
        var check_length = password.length >= 8;
        var patt = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z\d])/;
        var result = patt.test(password) && check_length;
        return result;
    }

    $('#password').blur(function(){
        var password = $('#password').val();
        if(!(is_basic16(password) || is_comprehensive8(password))){
            $('#password').css('border-color', 'red');
            $('#strength').show();
        }

    });

    $('#password').focus(function(){
        $('#password').css('border-color','#888');
        $('#strength').hide();
    });

</script>
</body>
</html>
