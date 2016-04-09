<#macro page_head>
</#macro>

<#macro page_body>
</#macro>

<#macro display_page>
<!DOCTYPE html>
<html lang="en" ng-app="vault">
<head>
    <meta charset="UTF-8">
    <title>Vault5431</title>
    <link href="/bootstrap.min.css" rel="stylesheet">
    <script type="text/javascript" src="/jquery-1.11.3.min.js"></script>
    <script type="text/javascript" src="/bootstrap.min.js"></script>
    <script type="text/javascript" src="/sjcl.js"></script>
    <link href="/vault.css" rel="stylesheet">
    <@page_head/>
</head>
<body>
<div class="col-sm-3 col-md-2 sidebar">
    <ul class="nav nav-sidebar">
        <li><a href="/home">Vault</a></li>
        <li><a href="/generator">Password Generator</a></li>
    <#--<li><a href="">Settings</a></li>-->
        <li><a href="/userlog">User Log</a></li>
        <#--<li><a href="/syslog">System Log</a></li>-->
        <li><a href="" id="logout" onclick="logout()">Logout</a></li>
    </ul>
</div>
<div class="page-header mainheader">
    <h1>Vault 5431
        <small>Your trusty password manager</small>
    </h1>
</div>
    <@page_body/>
<script type="text/javascript" src="/angular.min.js"></script>
<script>
    function logout () {
        document.cookie = "token=;expires=Thu, 01 Jan 1970 00:00:01 GMT;";
        sessionStorage.removeItem("password");
        window.location = "/";
    }
</script>
</body>
</html>
</#macro>
