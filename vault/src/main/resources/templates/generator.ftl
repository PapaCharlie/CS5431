<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10">
    <form action="/generator" method="post" class="form-inline">
        <div class="input-group">
            <input style="width: 100px;" type="number" min="5" max="99" name="length"
                   class="form-control" placeholder="Password Length" required="" autofocus="" value="${length}">
            <span class="input-group-btn">
                <button class="btn btn-success" type="submit">Generate</button>
            </span>
        </div>
    </form>
    <div class="panel panel-default">
        <div class="panel-body">
            ${randompassword?html}
        </div>
    </div>
</div>
</#macro>

<@display_page/>