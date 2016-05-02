<#include "vault.ftl">

<#macro page_head>
<link rel="stylesheet" type="text/css" href="/generator.css">
</#macro>

<#macro page_body>
<div class="col-sm-9 col-md-10">
    <form action="/generator" method="post" class="form-inline" id="generator">
        <div class="form-group">
            <label for="length">Length</label>
            <input style="width: 100px;" type="number" min="6" max="100" name="length" id="length"
                   class="form-control" placeholder="Password Length" required="" autofocus="" value="12">
        </div>
        <div class="checkbox">
            <label class="checkbox-inline">
                <input type="checkbox" name="lower" id="lower" checked> a-z
            </label>
            <label class="checkbox-inline">
                <input type="checkbox" name="upper" id="upper" checked> A-Z
            </label>
            <label class="checkbox-inline">
                <input type="checkbox" name="numbers" id="numbers" checked> 1-9
            </label>
            <label class="checkbox-inline">
                <input type="checkbox" name="symbols" id="symbols" checked> !@#$
            </label>
            <label class="checkbox-inline">
                <input type="checkbox" name="pronounceable" id="pronounceable" data-toggle="tooltip" title="Default no 1-9 and !@#$" data-trigger="click"> Pronounceable
            </label>
        </div>
        <button class="btn btn-success" type="submit">Generate</button>
    </form>
    <div class="panel panel-default">
        <div class="panel-body generated-password" id="generatedPassword">
        </div>
    </div>
    <#--<button class="btn btn-primary" data-toggle="modal" data-target="#newPass">Create New Password</button>-->
    <span class="addicon glyphicon glyphicon-plus" data-toggle="modal" data-target="#newPass" aria-hidden="true"></span>
    <div id="newPass" class="modal fade" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Create New Password</h4>
                </div>
                <div class="modal-body">
                    <form class="form-signin" id="newPasswordForm">
                        <input type="text" name="name" class="form-control" maxlength="500" placeholder="Website Name" required>
                        <input type="url" name="url" class="form-control" maxlength="500" placeholder="URL" required>
                        <input type="text" name="username" id="username" maxlength="500" class="form-control" placeholder="Account username" required>
                        <input type="password" name="password" id="inputPassword" maxlength="500" class="form-control" placeholder="Password" required>
                        <textarea form="newPasswordForm" name="notes" class="form-control" maxlength="1000" placeholder="Secure Notes (Optional- max 1000 characters)"></textarea>
                        <button class="btn btn-lg btn-primary btn-block" type="submit">Create New Password</button>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                </div>
            </div>

        </div>
    </div>
    <script>
        $(function () {
            $('[data-toggle="tooltip"]').tooltip();
            $('input#pronounceable').on('change', function () {
                if ($(this).is(':checked')) {
                    document.getElementById("length").min = "12";
                    document.getElementById("numbers").disabled = true;
                    document.getElementById("symbols").disabled = true;
                } else {
                    document.getElementById("length").min = "6";
                    document.getElementById("numbers").disabled = false;
                    document.getElementById("symbols").disabled = false;
                }
            });

            $("#generator").submit(function (event) {
                event.preventDefault();
                var length = $(this).find(':input#length')[0].value;
                var checkboxes = $(this).find(':checkbox');
                var values = {};
                values.length = length;
                checkboxes.each(function () {
                    if (this.name) {
                        values[this.name] = this.checked;
                    }
                });
                $.post('/generator', values, function (data) {
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
