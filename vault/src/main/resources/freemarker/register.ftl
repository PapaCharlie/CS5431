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
        <label for="phonesignup">Your Phone Number (of form: 123-456-7890) </label>
        <p><input type="tel" name="phoneNumber" placeholder="Phone Number" pattern="^\d{3}-\d{3}-\d{4}$" required></p>
        <p><input type="submit" value="Sign Up"></p>
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
            $passwordField.val(fromBits(hash("auth" + $passwordField.val())));
        });
    });
</script>
</body>
</html>
