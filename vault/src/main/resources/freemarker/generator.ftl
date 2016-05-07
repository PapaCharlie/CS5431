<#include "vault.ftl">

<#macro page_head>
<link rel="stylesheet" type="text/css" href="/generator.css">
<script type="text/javascript" src="/generator.js"></script>
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
                var password = generatePassword(values.length, values.lower, values.upper, values.numbers, values.symbols, values.pronounceable);
                $("#generatedPassword").text(password);
            });
        });
    </script>
</div>
</#macro>

<@display_page/>
