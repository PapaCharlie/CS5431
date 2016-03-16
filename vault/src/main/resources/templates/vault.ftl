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
        <li><a href="">Preferences</a></li>
        <li><a href="/log">Logs?</a></li>
        <li><a href="">Logout</a></li>
    </ul>
    <!-- <ul class="nav nav-sidebar">
      <li><a href="">Home</a></li>
      <li><a href="">Password Generator</a></li>
      <li><a href="">Settings</a></li>
      <li><a href="">Logs?</a></li>
      <li><a href="">Logout</a></li>
    </ul>     -->
</div>


<div class="page-header mainheader">
    <h1>Vault 5431
        <small>Your trusty password manager</small>
    </h1>
</div>

<!-- <div class="col-sm-9 col-md-10 sidebar">
  <table class="table table-striped">
    <thead>
      <tr>
        <th>#</th>
        <th>Header</th>
        <th>Header</th>
        <th>Header</th>
        <th>Header</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>1,001</td>
        <td>Lorem</td>
        <td>ipsum</td>
        <td>dolor</td>
        <td>sit</td>
      </tr>
      <tr>
        <td>1,002</td>
        <td>amet</td>
        <td>consectetur</td>
        <td>adipiscing</td>
        <td>elit</td>
      </tr>
      <tr>
        <td>1,003</td>
        <td>Integer</td>
        <td>nec</td>
        <td>odio</td>
        <td>Praesent</td>
      </tr>


    </tbody>
  </table>
</div> -->
<#if storedpasswords?has_content>
    <#list storedpasswords as password>
        <li>${password.name}</li>
    </#list>
</#if>


<div>
<#list storedpasswords as password>
    <li>${password.name}</li>
<#else>
    Zerp!
</#list>
</div>

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
        <div class="panel panel-default">
            <div class="panel-heading">
                <h4 class="panel-title">
                    <a data-toggle="collapse" data-parent="#accordion" href="#collapse1">
                        www.gmail.com</a>
                </h4>
            </div>
            <div id="collapse1" class="panel-collapse collapse">
                <div class="panel-body">
                    <div class="col-sm-4 col-md-4">myusername</div>
                    <div class="col-sm-4 col-md-4">mypassword</div>
                    <form method="post" action="/changePassword">
                    <button class="btn btn-warning" type="submit">Change password</button>
                        </form>
                </div>
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h4 class="panel-title">
                    <a data-toggle="collapse" data-parent="#accordion" href="#collapse2">
                        www.facebook.com</a>
                </h4>
            </div>
            <div id="collapse2" class="panel-collapse collapse">
                <div class="panel-body">
                    <div class="col-sm-4 col-md-4">myusername</div>
                    <div class="col-sm-4 col-md-4">mypassword</div>
                    <form method="post" action="/changePassword">
                    <button class="btn btn-warning" type="submit">Change password</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h4 class="panel-title">
                    <a data-toggle="collapse" data-parent="#accordion" href="#collapse3">
                        www.twitter.com</a>
                </h4>
            </div>
            <div id="collapse3" class="panel-collapse collapse">
                <div class="panel-body">
                    <div class="col-sm-4 col-md-4">myusername</div>
                    <div class="col-sm-4 col-md-4">mypassword</div>
                    <button class="btn btn-warning" type="button">Change password</button>
                </div>
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h4 class="panel-title">
                    <a data-toggle="collapse" data-parent="#accordion" href="#collapse4">
                        Cornell NetID</a>
                </h4>
            </div>
            <div id="collapse4" class="panel-collapse collapse">
                <div class="panel-body">
                    <div class="col-sm-4 col-md-4">myusername</div>
                    <div class="col-sm-4 col-md-4">mypassword</div>
                    <button class="btn btn-warning" type="button">Change password</button>
                </div>
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h4 class="panel-title">
                    <a data-toggle="collapse" data-parent="#accordion" href="#collapse5">
                        www.spotify.com</a>
                </h4>
            </div>
            <div id="collapse5" class="panel-collapse collapse">
                <div class="panel-body">
                    <div class="col-sm-4 col-md-4">myusername</div>
                    <div class="col-sm-4 col-md-4">mypassword</div>
                    <button class="btn btn-warning" type="button">Change password</button>
                </div>
            </div>
        </div>

    </div>
</div>


</body>
</html>