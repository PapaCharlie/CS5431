<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10 newpass">
    <form method="post" action="/savepassword" class="form-signin" id="newPasswordForm">
        <h4 class="form-signin-heading">New Password</h4>
        <input type="text" name="name" class="form-control" placeholder="Website Name" required>
        <input type="text" name="url" class="form-control" placeholder="URL" required>
        <input type="text" name="username" id="username" class="form-control" placeholder="Account username" required>
        <input type="password" name="password" id="inputPassword" class="form-control" placeholder="Password" required>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Save</button>
    </form>
</div>

    <#if empty??>
    <div class="col-sm-9 col-md-10 col-sm-offset-3 col-md-offset-2" ng-controller="PasswordCtrl">
        <h4 class="storedpasswords-heading">Stored Accounts</h4>
        <div class="panel-group" id="accordion">
            No stored passwords!
        </div>
    </div>
    <#else>
    <div class="col-sm-9 col-md-10 col-sm-offset-3 col-md-offset-2" ng-controller="PasswordCtrl">
        <h4 class="storedpasswords-heading">Stored Accounts</h4>
        <div class="panel-group" id="accordion">
            
            <#--<div class="panel panel-default" ng-repeat="password in passwords">-->
                <#--<div class="panel-heading">-->
                    <#--<h4 class="panel-title">-->
                        <#--<a data-toggle="collapse" data-parent="#accordion" ng-attr-href="{{password.id}}">-->
                            <#--{{password.name}}</a>-->
                    <#--</h4>-->

                <#--</div>-->
                <#--<div ng-attr-id="{{password.id}}" class="panel-collapse collapse">-->
                    <#--<div class="panel-body">-->
                        <#--<div class="row">-->
                            <#--<div class="col-sm-4 col-md-4">URL: {{password.url}}</div>-->
                        <#--</div>-->
                        <#--<div class="row">-->
                            <#--<div class="col-sm-4 col-md-4">Username: {{password.username}}</div>-->
                            <#--<div ng-attr-id="{{password.name + 'pass'}}" class="col-sm-4 col-md-4">Password:-->
                                <#--<input type="password" ng-attr-value="{{password.password}}">-->
                                <#--<button class="reveal" id="{{password.name}}reveal">Reveal</button>-->
                            <#--</div>-->
                            <#--<form method="post" action="/vault/changepassword">-->
                                <#--<input type="hidden" name="name" value="{{password.name}}">-->
                                <#--<button class="btn btn-warning" type="submit">Change password</button>-->
                            <#--</form>-->

                        <#--</div>-->
                    <#--</div>-->
                <#--</div>-->
            <#--</div>-->
        </div>
    </div>
    </#if>

<script>
    $(function () {
        if (sessionStorage.getItem("password")) {
            var data = ${payload};
            var salt = sjcl.codec.base64url.toBits(data.salt);
            var password = sjcl.codec.base64url.toBits(sessionStorage.getItem("password"));
            var key = sjcl.hash.sha256.hash(sjcl.bitArray.concat(salt, password));
            var passwords = data.passwords.map(function (encryptedPassword) {
                return JSON.parse(sjcl.decrypt(key, JSON.stringify(encryptedPassword)));
            });
            console.log(passwords);
            getAccordions(passwords);

        } else {
            document.cookie = "token=;expires=Thu, 01 Jan 1970 00:00:01 GMT;";
            window.location = "/";
        }

        $(document).on("click", ".reveal", function () {
            var type = $(this).siblings("input").attr('type');
            if (type == 'password') {
                console.log("reveal");
                $(this).siblings("input").attr('type', 'text');
                $(this).html("Hide");
            }
            else {
                console.log("hide");
                $(this).siblings("input").attr('type', 'password');
                $(this).html("Reveal");
            }
        });

        angular.module('vault', [])
                .controller('PasswordCtrl', function ($scope) {
                    $scope.passwords = data.passwords.map(function (encryptedPassword) {
                        return JSON.parse(sjcl.decrypt(key, JSON.stringify(encryptedPassword)));
                    });
                });

        $("#newPasswordForm").submit(function (event) {
            event.preventDefault();
            var $inputs = $('#newPasswordForm :input');
            var values = {};
            $inputs.each(function () {
                if (this.name) {
                    values[this.name] = $(this).val();
                }
            });
            values["id"] = '_' + Math.random().toString(36).substr(2, 9);
            $.post('/savepassword', {newPassword: sjcl.encrypt(key, JSON.stringify(values))}, function (data) {
                var response = JSON.parse(data);
                if(response.success) {
                    window.location = "/home";
                } else {
                    alert(response.error);
                }
            });
        });

    })

    function getAccordions(passwords){
        passwords.forEach(function(entry) {
            console.log(entry.name);
            $("#accordion").append(
                    "<div class='panel panel-default'>"+
                        "<div class='panel-heading'>"+
                            "<h4 class='panel-title'>"+
                                "<a data-toggle='collapse' data-parent='#accordion' href=#"+entry.id+">"+
                                    entry.name+"</a>"+
                            "</h4>"+
                        "</div>"+
                        "<div id="+entry.id+" class='panel-collapse collapse'>"+
                            "<div class='panel-body'>"+
                                "<div class='row'>"+
                                    "<div class='col-sm-4 col-md-4'>URL: "+entry.url+"</div>"+
                                "</div>"+
                                "<div class='row'>"+
                                    "<div class='col-sm-4 col-md-4'>Username: "+entry.username+"</div>"+
                                        "<div ng-attr-id="+entry.name+" class='col-sm-4 col-md-4'>Password:"+
                                            "<input type='password' value="+entry.password+">"+
                                            "<button class='reveal' id="+entry.id+"reveal>Reveal</button>"+
                                        "</div>"+
                                        "<form method='post' action='/vault/changepassword'>"+
                                            "<input type='hidden' name='name' value="+entry.name+">"+
                                            "<button class='btn btn-warning' type='submit'>Change password</button>"+
                                        "</form>"+
                                "</div>"+
                            "</div>"+
                        "</div>"+
                    "</div>"

            );

        });
    }
</script>
</#macro>

<@display_page/>