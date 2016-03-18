<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vault5431</title>
    <link href="/bootstrap.min.css" rel="stylesheet">
    <link href="vault.css" rel="stylesheet">
    <script src="jquery-1.11.3.min.js"></script>
    <script src="/bootstrap.min.js"></script>

</head>

<body>
<div class="col-sm-3 col-md-2 sidebar">
    <ul class="nav nav-sidebar">
        <li><a href="">Vault</a></li>
        <li><a href="/generator">Password Generator</a></li>
        <li><a href="">Settings</a></li>
        <li><a href="/userlog">User Log</a></li>
        <li><a href="/syslog">System Log</a></li>
        <li><a href="">Logout</a></li>
    </ul>

</div>


<div class="page-header mainheader">
    <h1>Vault 5431
        <small>Your trusty password manager</small>
    </h1>
</div>


<#--<#if storedpasswords?has_content>-->
    <#--<#list storedpasswords as password>-->
        <#--<li>${password.name}</li>-->
    <#--</#list>-->
<#--</#if>-->




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
                        <a data-toggle="collapse" data-parent="#accordion" href="#${password.name}">
                        ${password.name}</a>
                    </h4>

                </div>
                <div id="${password.name}" class="panel-collapse collapse">
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


</body>
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
</html>