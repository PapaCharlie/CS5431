<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vault5431</title>
    <link rel="icon" href="/favicon.ico?v=2" />
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
</head>
<body>
<div class="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Log in</h2>
    <form action="/twofactor" method="post" id="twoFactorForm" name="twoFactorForm" class="login-container">
        <p><input type="number" name="authCode" id="authCode" placeholder="Code" autofocus required></p>
        <p><input type="submit" value="Submit code"></p>
    <#if error??>
        <p class="has-error">${error}</p>
    </#if>
    </form>
</div>
</body>
</html>
