<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vault5431</title>
    <link href="/bootstrap.min.css" rel="stylesheet">
    <link href="vault.css" rel="stylesheet">
    <script src="jquery-1.11.3.min.js"></script>
    <script src="/bootstrap.min.js"></script>

</head>
<body>
<div class="col-sm-3 col-md-2 sidebar">
    <ul class="nav nav-sidebar">
        <li><a href="/vault">Vault</a></li>
        <li><a href="/generator">Password Generator</a></li>
        <li><a href="">Settings</a></li>
        <li><a href="/userlog">User Log</a></li>
        <li><a href="/syslog">System Log</a></li>
        <li><a href="">Logout</a></li>
    </ul>

</div>
<div class="page-header mainheader">
    <h1>Vault 5431
        <small>Your trusty password manager</small>
    </h1>
</div>


<div class="col-sm-9 col-md-10">
    <table class="logtable" style="width:100%">
        <tr>
            <th>Log Type</th>
            <th>IP</th>
            <th>Affected User</th>
            <th>Timestamp</th>
            <th>Message</th>
        </tr>
    <#list sysloglist?reverse as log>
        <tr>
            <td>${log.logType}</td>
            <td>${log.ip}</td>
            <td>${log.affectedUser}</td>
            <td>${log.timestamp}</td>
            <td>${log.message}</td>
        </tr>
    </#list>
    </table>
</div>

</body>

</html>