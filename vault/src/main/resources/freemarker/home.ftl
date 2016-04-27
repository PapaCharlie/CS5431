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
    </div>
</div>

<script>
    $(function () {
        var key;
        var passwords;
        if (sessionStorage.getItem("password")) {
            $.get("/passwords", function (payload) {
                var data = JSON.parse(payload);
                if (data && data.hasOwnProperty("passwords") && data.hasOwnProperty("salt")) {
                    key = hash(sjcl.bitArray.concat(fromB64(data.salt), fromB64(sessionStorage.getItem("password"))));
                    passwords = decryptPasswords(data.passwords, key);
                    getAccordions(passwords);
                } else {
                    console.log("Bad payload");
                }
            });
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

        $("#newPasswordForm").on('submit', function (event) {
            event.preventDefault();
            var inputs = $(this).find(':input');
            var values = {};
            inputs.each(function () {
                if (this.name) {
                    values[this.name] = encrypt(key, this.value);
                }
            });
            $.post('/savepassword', {newPassword: JSON.stringify(values)}, function (data) {
                var response = JSON.parse(data);
                if (response.success) {
                    window.location = "/home";
                } else {
                    alert(response.error);
                }
            });
        });

        $(".changePasswordForm").on('submit', function (event) {
            event.preventDefault();
            var inputs = $(this).find(':input');
            var id;
            var values = {};
            inputs.each(function () {
                if (this.name) {
                    if (this.name !== "id") {
                        values[this.name] = encrypt(key, this.value);
                    } else {
                        id = this.value;
                    }
                }
            });
            $.post('/changepassword', {
                id: id,
                changedPassword: JSON.stringify(values)
            }, function (data) {
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

</script>
</#macro>

<@display_page/>