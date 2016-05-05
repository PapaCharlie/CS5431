<#include "vault.ftl">

<#macro page_head>
<link rel="stylesheet" href="/jquery-ui.min.css">
<script type="text/javascript" src="/userlog.js"></script>
<script type="text/javascript" src="/jquery-ui.min.js"></script>
</#macro>

<#macro page_body>






<div class="col-sm-9 col-md-10">
    <div style="border:1px solid black; padding:5px">
        <p>
        <center style="font-size:20px"> Log Search</center>
        </p>
        <p>
        <div class="input-group">
            <div class="input-group-btn">
                <button class="btn btn-primary dropdown-toggle" type="button" data-toggle="dropdown">Log Type
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
        </p>
        <p>
        <div class="input-group">
            <div class="input-group-btn">
                <button class="btn btn-primary dropdown-toggle" type="button" data-toggle="dropdown">Messages </button>
            </div>
            <input id="message" type="text" class="form-control" placeholder="Type here...">
        </div>
        </p>
        <p>
        <div class="input-group">
            <div class="input-group-btn">
                <button class="btn btn-primary dropdown-toggle" type="button" data-toggle="dropdown">IP Address </button>
            </div>
            <input id="ipText" type="text" class="form-control" placeholder="Type here...">
        </div>
        </p>
        <p>
        <div>
            <div class="row">
                <div class="form-group col-xs-6">
                    <div class="input-group col-xs-6">
                        <label for="datepicker1" class="input-group-addon btn"><span class="glyphicon glyphicon-calendar"></span>
                            Start Date:
                        </label>
                        <input id="datepicker1" type="text" class="form-control" />
                    </div>
                </div>
                <div class="form-group col-xs-6">
                    <div class="input-group col-xs-6">
                        <label for="datepicker2" class="input-group-addon btn"><span class="glyphicon glyphicon-calendar"></span>
                            End Date:
                        </label>
                        <input id="datepicker2" type="text" class="form-control" />
                    </div>
                </div>
            </div>
        </div>
        </p>
        <p>
            <button id="searchAll" class="btn btn-danger"> Search </button>
            <button id="clear" class="btn btn-danger"> Clear </button>
        </p>
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
                    <td class="logType">${log.logType}</td>
                    <td class="ip">${log.ip}</td>
                    <td class="date">${log.timestamp}</td>
                    <td class="search">${log.message?html}</td>
                </tr>
            </#list>
        </table>
    </div>
</div>
</#macro>

<@display_page/>