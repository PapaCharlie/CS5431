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
        <li><a href="/vault">Vault</a></li>
        <li><a href="/generator">Password Generator</a></li>
        <li><a href="">Settings</a></li>
        <li><a href="">Preferences</a></li>
        <li><a href="/log">Logs?</a></li>
        <li><a href="">Logout</a></li>
    </ul>

</div>
<div class="page-header mainheader">
    <h1>Vault 5431 <small>Your trusty password manager</small></h1>
</div>
<div class="col-sm-9 col-md-10">
    <form action="/generate">
        <input style="width: 20%; display: inline-block" type="number" min="1" name="length" class="form-control" placeholder="Password Length" required="" autofocus="">
        <button class="btn btn-success" type="submit">Generate</button>
    </form>

    ${randompassword}
</div>
</body>

</html>