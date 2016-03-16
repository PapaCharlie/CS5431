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
        <li><a href="">Password Generator</a></li>
        <li><a href="">Settings</a></li>
        <li><a href="">Preferences</a></li>
        <li><a href="">Logs?</a></li>
        <li><a href="">Logout</a></li>
    </ul>

</div>
<div class="page-header mainheader">
    <h1>Vault 5431 <small>Your trusty password manager</small></h1>
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
        <#--<tr>-->
            <#--<td>Jill</td>-->
            <#--<td>Smith</td>-->
            <#--<td>50</td>-->
        <#--</tr>-->
        <#--<tr>-->
            <#--<td>Eve</td>-->
            <#--<td>Jackson</td>-->
            <#--<td>94</td>-->
        <#--</tr>-->
        <#list userloglist as entry>
        <tr>
            <#list entry as col>
                <td>${col}</td>
            </#list>
        </tr>
        </#list>
    </table>
</div>
<#--<li>${log0}</li>-->

<#--<li>${log1}</li>-->
<#--<li>${log2}</li>-->
<#--<li>${log3}</li>-->
<#--<li>${log4}</li>-->
<#--&lt;#&ndash;${list[0]}&ndash;&gt;-->
<#--<#if big>-->
<#--say hi-->
<#--</#if>-->


</body>

<#--<#list [1,2,3]>-->
<#--<ul>-->
    <#--<#items as x>-->
        <#--<li>${x?index}</li>-->
    <#--</#items>-->
<#--</ul>-->
<#--</#list>-->
<#--<#list userloglist as entry>-->
    <#--<#list entry as col>-->
        <#--<li>${col}</li>-->
    <#--</#list>-->
<#--</#list>-->

</html>