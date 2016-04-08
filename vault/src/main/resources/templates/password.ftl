<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script src="jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/login.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>

</head>

<script>
    <#if salt??>
    var salt = sjcl.codec.base64.toBits("${salt}");
    </#if>

    $('#passwordForm').submit(function () {
        var password = sjcl.codec.utf8String.toBits($('#password'));
        sjcl.hash.sha256.hash(password + salt);
        txt.val("updated " + txt.val());
    });


</script>


<div class="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Log in</h2>

    <form action="/" method="post" id="passwordForm" class="login-container">
        <p><input type="password" name="password" placeholder="Password" id="password"></p>
        <p><input type="submit" value="Log in"></p>
    <#if error??>
        <p>${error}</p>
    </#if>
    </form>


    <!-- <form action="vault" id="form" class="login-container" method="post" onsubmit="sendLoginInfo()">
       <p><input type="text" name="username" placeholder="Username"></p>
       <p><input type="password" name="password" placeholder="Password"></p>
       <p><input type="submit" value="Log in"></p>
     </form>
     -->


</div>


</html>