<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Vault5431</title>
    <link rel="stylesheet" type="text/css" href="/login.css">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
</head>
<body>
<div class="login">
    <div class="login-triangle"></div>
    <h2 class="login-header">Verify Phone Number</h2>
    <div class="login-container">
        <#if form??>
            <form action="" method="post" id="verifyPhoneNumberForm" name="verifyPhoneNumberForm"
                  class="login-container">
                <p><input type="number" name="verificationCode" id="verificationCode" placeholder="Verification Code"
                          autofocus required></p>
                <p><input type="submit" value="Submit code"></p>
            </form>
        <#elseif success??>
            <p>
                Your phone number has been verified! Please click here to <a href="/">login</a>.
            </p>
        <#elseif error??>
            <p class="has-error">
                This is not the number that was given to you. Your account has been deleted, you may try again <a href="/register">here</a>.
            </p>
        <#else>
            This page does not exist!
        </#if>
        <p>
            Not a member yet ? <a href="/register" class="to_register">Join us</a>
        </p>
    </div>

</div>
</body>
</html>
