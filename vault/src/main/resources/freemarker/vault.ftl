<#macro page_head>
</#macro>

<#macro page_body>
</#macro>

<#macro display_page>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vault5431</title>
    <link href="/bootstrap.min.css" rel="stylesheet">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/bootstrap.min.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>
    <script type="text/javascript" src="/clipboard.min.js"></script>
    <script type="text/javascript" src="/home.js"></script>
    <script type="text/javascript" src="/crypto.js"></script>
    <link href="/vault.css" rel="stylesheet">
    <@page_head/>
</head>
<body>
<div class="col-sm-3 col-md-2 sidebar">
    <ul class="nav nav-sidebar">
        <li id="homeLink"></li>
        <li><a href="/generator">Password Generator</a></li>
        <li><a id="sharedpasswordsLink" href="/sharedpasswords">Shared Passwords </a></li>
        <li><a href="/settings">Settings</a></li>
        <li><a href="/userlog">User Log</a></li>
        <li><a href="" id="logout">Logout</a></li>
    </ul>
</div>
<div class="page-header mainheader">
    <h1>Vault 5431
        <small>Your trusty password manager</small>
    </h1>
</div>
    <@page_body/>
<script>
    $(function () {

        $.get("/numshared", {}, function (data) {
            var response = JSON.parse(data);
            if (response.success && response.numshared > 0) {
                $("#sharedpasswordsLink").append($("<span/>", {'class': 'badge', 'text': response.numshared}));
            }
        });

        $("#homeLink").append($("<a/>", {'href': '/home', 'text': getUsernameFromCookie() + "'s Vault"}));

        $("#logout").click(function (e) {
            e.preventDefault();
            sessionStorage.removeItem("password");
            window.location.href = "/logout";
        });

        if (!sessionStorage.getItem("password")) {
            window.location.href = "/logout";
        }
    });
</script>
</body>
</html>
</#macro>
