<#include "vault.ftl">

<#macro page_body>
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
</#macro>

<@display_page/>