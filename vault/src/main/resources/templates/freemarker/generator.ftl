<#include "vault.ftl">

<#macro page_head>
    <link rel="stylesheet" type="text/css" href="/generator.css">
</#macro>

<#macro page_body>
<div class="col-sm-9 col-md-10">
    <form action="/generator" method="post" class="form-inline" id="generator">
        <div class="input-group">
            <input style="width: 100px;" type="number" min="5" max="99" name="length" id="length"
                   class="form-control" placeholder="Password Length" required="" autofocus="" value="12">
            <span class="input-group-btn">
                <button class="btn btn-success" type="submit">Generate</button>
            </span>
        </div>
    </form>
    <div class="panel panel-default">
        <div class="panel-body generated-password" id="generatedPassword">
        <#--${randompassword?html}-->
        </div>
    </div>
    <script>
        $(function () {
            $("#generator").submit(function (event) {
                event.preventDefault();
                $.post('/generator', {length: $("#length").val()}, function (data) {
                    var response = JSON.parse(data);
                    if (response.success) {
                        $("#generatedPassword").text(response.password);
                    } else {
                        alert(response.error);
                    }
                });
            });
        });
    </script>
</div>
</#macro>

<@display_page/>
