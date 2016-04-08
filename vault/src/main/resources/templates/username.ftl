<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script src="jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="login.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>

</head>

<script>
    $.getJSON("https://api.ipify.org?format=jsonp&callback=?",
            function (json) {
                $('input[name="ip"]').val(json.ip);
            }
    );

</script>


<div class="login">
    <div class="login-triangle"></div>

    <h2 class="login-header">Log in</h2>


    <form action="/password" method="post" id="form" class="login-container">
        <p><input type="text" name="username" placeholder="Username" autofocus></p>
        <input type="hidden" name="ip">
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