<#include "vault.ftl">

<#macro page_head>
<script type="text/javascript" src="/userlog.js"></script>
</#macro>

<#macro page_body>
<div class="col-sm-9 col-md-10">
    <div class="input-group">
        <div class="input-group-btn">
            <button class="btn btn-primary dropdown-toggle" type="button" data-toggle="dropdown">Search
                <span class="caret"></span>
            </button>

            <ul class="dropdown-menu" id="logTypes">
                <li><a href="#">Display All</a></li>
                <li value="Info"><a href="#">Info</a></li>
                <li value="Error"><a href="#">Error</a></li>
                <li value="Warning"><a href="#">Warning</a></li>
            </ul>
        </div>
        <input id="filter" type="text" class="form-control" placeholder="Type here...">
    </div>

    <div>
        <table class="logtable" style="width:100%">
            <tr>
                <th>Log Type</th>
                <th>IP</th>
                <th>Timestamp</th>
                <th>Message</th>
            </tr>
            <#list userloglist?reverse as log>
                <tr class="filterable">
                    <td>${log.logType}</td>
                    <td>${log.ip}</td>
                    <td>${log.timestamp}</td>
                    <td class="search">${log.message}</td>
                </tr>
            </#list>
        </table>
    </div>
</div>
</#macro>

<@display_page/>