<#include "vault.ftl">

<#macro page_head>
<script type="text/javascript" src="/userlog.js"></script>
</#macro>

<#macro page_body>
<div class="col-sm-9 col-md-10">
    <form action="/settings" method="post" class="form-horizontal" id="settingsForm">
        <div class="form-group">
            <label for="concurrentSessions" class="col-sm-4 control-label">Maximum number of concurrent users: </label>
            <input style="width: 100px;" type="number" min="1" max="20" name="concurrentSessions" id="concurrentSessions"
                   class="form-control" required value="${concurrentSessions!5}">
        </div>
        <div class="form-group">
            <label for="sessionLength" class="col-sm-4 control-label">Maximum session length: </label>
            <input style="width: 100px;" type="number" min="2" max="1440" name="sessionLength" id="sessionLength"
                   class="form-control col-sm-6" required value="${sessionLength!60}">
        </div>
        <button class="btn btn-success" type="submit">Save</button>
    </form>
</div>
<script>
    $("#settingsForm").on('submit', function (event) {
        event.preventDefault();
        var values = {};
        $(this).find(':input').each(function () {
            if (this.name) {
                values[this.name] = this.value;
            }
        });
        $.post('/settings', values, function (data) {
            var response = JSON.parse(data);
            if (response.success) {
                window.location = "/settings";
            } else {
                alert(response.error);
            }
        });
    });
</script>
</#macro>

<@display_page/>