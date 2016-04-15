<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10 newpass">
    <form method="post" action="/savepassword" class="form-signin" id="newPasswordForm">
        <h4 class="form-signin-heading">New Password</h4>
        <input type="text" name="name" class="form-control" placeholder="Website Name" required>
        <input type="url" name="url" class="form-control" placeholder="URL" required>
        <input type="text" name="username" id="username" class="form-control" placeholder="Account username" required>
        <input type="password" name="password" id="inputPassword" class="form-control" placeholder="Password" required>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Save</button>
    </form>
</div>

<div class="col-sm-9 col-md-10 col-sm-offset-3 col-md-offset-2">
    <h4 class="storedpasswords-heading">Stored Accounts</h4>
    <div class="panel-group" id="accordion">
        <#if empty??>
            No stored passwords!
        </#if>
    </div>
</div>

<script>
    $(function () {
        if (sessionStorage.getItem("password")) {
            var data = ${payload};
            if (data) {
                var salt = sjcl.codec.base64url.toBits(data.salt);
                var password = sjcl.codec.base64url.toBits(sessionStorage.getItem("password"));
                var key = sjcl.hash.sha256.hash(sjcl.bitArray.concat(salt, password));
                var passwords = data.passwords.map(function (encryptedPassword) {
                    var newPassword = JSON.parse(sjcl.decrypt(key, JSON.stringify(encryptedPassword)));
                    newPassword.id = encryptedPassword.id;
                    return newPassword;
                });
                getAccordions(passwords);
            }
        } else {
            document.cookie = "token=;expires=Thu, 01 Jan 1970 00:00:01 GMT;";
            window.location = "/";
        }

        $(document).on("click", ".reveal", function () {
            var type = $(this).siblings("input").attr('type');
            if (type == 'password') {
                $(this).siblings("input").attr('type', 'text');
                $(this).html("Hide");
            }
            else {
                $(this).siblings("input").attr('type', 'password');
                $(this).html("Reveal");
            }
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
            $.post('/savepassword', {newPassword: sjcl.encrypt(key, JSON.stringify(values))}, function (data) {
                var response = JSON.parse(data);
                if (response.success) {
                    window.location = "/home";
                } else {
                    alert(response.error);
                }
            });
        });

        $("#changePasswordForm").submit(function (event) {
            event.preventDefault();
            var $inputs = $('#changePasswordForm :input');
            var values = {};
            $inputs.each(function () {
                if (this.name) {
                    values[this.name] = $(this).val();
                }
            });
            var id = values.id;
            delete values.id;
            $.post('/changepassword', {id: id, changedPassword: sjcl.encrypt(key, JSON.stringify(values))}, function (data) {
                var response = JSON.parse(data);
                if (response.success) {
                    window.location = "/home";
                } else {
                    alert(response.error);
                }
            });
        });

        $('[data-toggle="tooltip"]').tooltip();
        $('.copy').each(function (index) {
            var $copy = $(this);
            var c = new Clipboard(this, {
                target: function (trigger) {
                    var v = document.createElement("input");
                    v.className = "temp"
                    v.value = trigger.previousElementSibling.value;
                    $("div.panel").append(v);
                    return v;
                }
            });

            c.on('success', function (e) {
                $("input").remove(".temp");
                $copy.on("click", function (e) {
                    e.preventDefault();
                    $(this).tooltip("show");
                });
                $copy.mouseout(function (e) {
                    e.preventDefault();
                    $copy.tooltip("destroy");
                });
                console.info('Action:', e.action);
                console.info('Text:', e.text);
                console.info('Trigger:', e.trigger);
            });
        });
    });


    $(document).on("click", ".delete", function () {
        var r = confirm("Are you sure you want to delete this Account?");
        if (r == true) {
            $(this).closest("div.panel-default").remove();
            var entryid = $(this).attr("data-id");
            console.log(entryid);
            $.post("/deletepassword", {id: entryid}, function (data) {
                var response = JSON.parse(data);
                if (response.success) {
                    window.location = "/home";
                } else {
                    alert(response.error);
                }
            });
        }
    });

    function getAccordions(passwords) {
        passwords.forEach(function (entry) {
            $("#accordion").append(
                    "<div class='panel panel-default'>" +
                        "<div class='panel-heading'>" +
                            "<h4 class='panel-title'>" +
                                "<a data-toggle='collapse' data-parent='#accordion' href=#" + entry.id + ">" +
                                entry.name + "</a>" +
                                "<button class='delete btn btn-danger btn-xs' data-id='"+entry.id+"' style='float: right' aria-hidden='true'>Delete</button>" +
                            "</h4>" +
                        "</div>" +
                        "<div id=" + entry.id + " class='panel-collapse collapse'>" +
                            "<div class='panel-body'>" +
                                "<div class='row'>" +
                                    "<div class='col-sm-4 col-md-4'>URL: " + entry.url + "</div>" +
                                "</div>" +
                                "<div class='row'>" +
                                    "<div class='col-sm-4 col-md-4'>Username: " + entry.username + "</div>" +
                                    "<div id=" + entry.name + " class='col-sm-4 col-md-4'>Password:" +
                                        "<input id='" + entry.id + "copy' type='password' value='" + entry.password + "'>" +
                                        "<button class='copy btn btn-default btn-sm' data-toggle='tooltip' title='Copied!' data-placement='bottom' data-trigger='click' data-clipboard-action='copy' data-clipboard-target='#" + entry.id + "copy'>Copy</button>" +
                                        "<button class='reveal btn btn-default btn-sm' id='" + entry.id + "reveal'>Reveal</button>" +
                                    "</div>" +
                                    "<button type='button' class='btn btn-warning' data-toggle='modal' data-target='#" + entry.id + "modal'>Edit Account Info</button>" +
                                    "<div id='" + entry.id + "modal' class='modal fade' role='dialog'>" +
                                        "<div class='modal-dialog'>" +
                                            <!-- Modal content-->
                                            "<div class='modal-content'>" +
                                                "<div class='modal-header'>" +
                                                    "<button type='button' class='close' data-dismiss='modal'>&times;</button>" +
                                                    "<h4 class='modal-title'>Edit Account Details</h4>" +
                                                "</div>" +
                                "<div class='modal-body'>" +
                                    "<form method='post' action='/changepassword' id='changePasswordForm' >" +
                                        "<input type='hidden' name='id' value='" + entry.id + "'>" +
                                        "<input type='text' name='name' class='form-control' placeholder='Website Name' value='" + entry.name + "' required>" +
                                        "<input type='url' name='url' class='form-control' placeholder='URL' value='" + entry.url + "' required>" +
                                        "<input type='text' name='username' class='form-control' placeholder='Username' value='" + entry.username + "' required>" +
                                        "<input type='text' name='password' class='form-control' placeholder='New Password' value='" + entry.password + "' required>" +
                                        "<button class='btn btn-primary' type='submit'>Save new password</button>" +
                                    "</form>" +
                                "</div>" +
                    "<div class='modal-footer'>" +
                        "<button type='button' class='btn btn-default' data-dismiss='modal'>Close</button>" +
                    "</div>" +
                    "</div>" +
                    "</div>" +
                    "</div>" +
//                                        "<form method='post' action='/vault/changepassword'>"+
//                                            "<input type='hidden' name='name' value='"+entry.name+"'>"+
//                                            "<button class='btn btn-warning' type='submit'>Change password</button>"+
//                                        "</form>"+
                    "</div>" +
                    "</div>" +
                    "</div>" +
                    "</div>"
            );

        });
    }

</script>
</#macro>

<@display_page/>