<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10 newpass">
    <form method="post" action="/savepassword" class="form-signin">
        <h4 class="form-signin-heading">New Password</h4>
        <input type="text" name="web" class="form-control" placeholder="Website Name" required="" autofocus="">
        <input type="text" name="url" id="url" class="form-control" placeholder="URL" required="" autofocus="">
        <!-- <label for="inputEmail" class="sr-only">Email address</label> -->
        <input type="text" name="username" id="username" class="form-control" placeholder="Account username" required=""
               autofocus="">
        <!-- <label for="inputPassword" class="sr-only">Password</label> -->
        <input type="password" name="password" id="inputPassword" class="form-control" placeholder="Password"
               required="">
        <!-- <div class="checkbox">
          <label>
            <input type="checkbox" value="remember-me"> Remember me
          </label>
        </div> -->
        <button class="btn btn-lg btn-primary btn-block" type="submit">Save</button>
    </form>
</div>

<div class="col-sm-9 col-md-10 col-sm-offset-3 col-md-offset-2">
    <h4 class="storedpasswords-heading">Stored Accounts</h4>
    <div class="panel-group" id="accordion">


        <#list storedpasswords as password>
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h4 class="panel-title">
                        <a data-toggle="collapse" data-parent="#accordion" href="#${password.uuid}">
                        ${password.name}</a>
                    </h4>

                </div>
                <div id="${password.uuid}" class="panel-collapse collapse">
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-sm-4 col-md-4">URL: ${password.website}</div>
                        </div>
                        <div class="row">
                            <div class="col-sm-4 col-md-4">Username: ${password.username}</div>
                            <div id="${password.name}pass" class="col-sm-4 col-md-4">Password:
                                <input type="password" value="${password.password}">
                                <button class="reveal" id="${password.name}reveal">Reveal</button>
                            </div>
                            <form method="post" action="/changepassword">
                                <input type="hidden" name="name" value="${password.name}">
                                <button class="btn btn-warning" type="submit">Change password</button>
                            </form>

                        </div>
                    </div>
                </div>
            </div>
        <#else>
            No stored passwords!
        </#list>
        <#--<div class="panel panel-default">-->
            <#--<div class="panel-heading">-->
                <#--<h4 class="panel-title">-->
                    <#--<a data-toggle="collapse" data-parent="#accordion" href="#collapse1">-->
                        <#--www.gmail.com</a>-->
                <#--</h4>-->
            <#--</div>-->
            <#--<div id="collapse1" class="panel-collapse collapse">-->
                <#--<div class="panel-body">-->
                    <#--<div class="col-sm-4 col-md-4">myusername</div>-->
                    <#--<div class="col-sm-4 col-md-4">mypassword</div>-->
                    <#--<button class="btn btn-warning" type="button">Change password</button>-->
                <#--</div>-->
            <#--</div>-->
        <#--</div>-->



    </div>
</div>

<script>
    $(document).on("click", ".reveal", function(){
        var type = $(this).siblings("input").attr('type');
        if(type == 'password'){
            console.log("reveal");
            $(this).siblings("input").attr('type', 'text');
            $(this).html("Hide");
        }
        else{
            console.log("hide");
            $(this).siblings("input").attr('type', 'password');
            $(this).html("Reveal");
        }
    })
</script>
</#macro>

<@display_page/>