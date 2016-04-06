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
    <script src="/jquery-1.11.3.min.js"></script>
    <script src="/bootstrap.min.js"></script>
    <link href="/vault.css" rel="stylesheet">
    <@page_head/>
</head>
<body>
    <div class="col-sm-3 col-md-2 sidebar">
        <ul class="nav nav-sidebar">
            <li><a href="/vault/home">Vault</a></li>
            <li><a href="/generator">Password Generator</a></li>
            <li><a href="">Settings</a></li>
            <li><a href="/vault/userlog">User Log</a></li>
            <li><a href="/vault/syslog">System Log</a></li>
            <li><a href="/logout">Logout</a></li>
        </ul>
    </div>
    <div class="page-header mainheader">
        <h1>Vault 5431
            <small>Your trusty password manager</small>
        </h1>
    </div>
    <@page_body/>
</body>
</html>
</#macro>
