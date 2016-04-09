<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>

</head>
<body>

<div class="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Log in</h2>
    <form action="/" method="post" id="loginForm" name="loginForm" class="login-container">
        <p><input type="text" name="username" id="username" placeholder="Username" autofocus></p>
        <p><input type="password" name="password" id="password" placeholder="Password"></p>
        <p><input type="submit" value="Log in"></p>
        <p>
            Not a member yet ? <a href="register.ftl" class="to_register">Join us</a>
        </p>
    <#if error??>
        <p>${error}</p>
    </#if>
    </form>
</div>
<script>
    $(document).ready(function () {

        sessionStorage.removeItem("password");

        $("#loginForm").submit(function (event) {
            $passwordField = $('#password');
            var hashedPassword = sjcl.hash.sha256.hash(sjcl.codec.utf8String.toBits($passwordField.val()));
            sessionStorage.setItem("password", sjcl.codec.base64url.fromBits(hashedPassword));
            var hash = sjcl.hash.sha256.hash(hashedPassword);
            $passwordField.val(sjcl.codec.base64url.fromBits(hash));
        });
    });
</script>

</body>


</html>
