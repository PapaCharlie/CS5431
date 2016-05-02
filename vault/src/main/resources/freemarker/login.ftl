<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vault5431</title>
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>
    <script type="text/javascript" src="/crypto.js"></script>
</head>
<body>
<div class="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Log in</h2>
    <div class="login-container">
        <form action="/" method="post" id="loginForm" name="loginForm">
            <p><input type="text" name="username" id="username" placeholder="Username" autofocus></p>
            <p><input type="password" name="password" id="password" placeholder="Password"></p>
            <p><input type="submit" value="Log in"></p>
        </form>
        <p>
            Not a member yet ? <a href="/register" class="to_register">Join us</a>
        </p>
        <#if error??>
            <p class="has-error">${error}</p>
        </#if>
    </div>

</div>
<script>
    $(document).ready(function () {
        if (sessionStorage.removeItem("password") && sessionStorage.removeItem("username")) {
            window.location.href = "/home";
        }
        $("#loginForm").submit(function (event) {
            sessionStorage.setItem("username", $(this).find("#username").val());
            var passwordField = $(this).find("#password");
            var hashedPassword = hash(passwordField.val());
            sessionStorage.setItem("password", toB64(hashedPassword));
            passwordField.val(toB64(hash("auth" + passwordField.val())));
        });
    });
</script>
</body>
</html>
