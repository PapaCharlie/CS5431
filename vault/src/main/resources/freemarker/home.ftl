<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10">

    <span id="plusbtn" class="addicon glyphicon glyphicon-plus" data-toggle="collapse" data-target="#newpassfunctions"
          aria-hidden="true"></span>
    <div class="input-group col-xs-6 col-sm-3 pull-right">
        <div class="input-group-btn">
            <button class="btn btn-primary dropdown-toggle" type="button" data-toggle="dropdown">Search</button>
        </div>
        <input id="search" type="text" class="form-control" placeholder="Type account name here...">
    </div>

    <div class="collapse" id="newpassfunctions">
        <form class="form-signin newpass" id="newPasswordForm">
            <h4 class="form-signin-heading">New Password</h4>
            <input type="text" name="name" class="form-control" maxlength="100" placeholder="Website Name" required>
            <input type="url" name="url" class="form-control" maxlength="500" placeholder="URL" required>
            <input type="text" name="username" id="username" class="form-control" maxlength="100"
                   placeholder="Account username" required>
            <div class="input-group">
                <input type="password" name="password" id="inputPassword" class="form-control" maxlength="100"
                       placeholder="Password" required>
                <span class="input-group-addon"><button id="genrandom" type="button">Random</button></span>
            </div>
            <p id="temprandom" class="hidden generated-password"></p>
            <textarea form="newPasswordForm" name="notes" class="form-control" maxlength="1000"
                      placeholder="Secure Notes (Optional- max 1000 characters)"></textarea>
            <button class="btn btn-lg btn-primary btn-block" type="submit">Create New Password</button>
        </form>
    </div>
</div>

<#--<div class="col-sm-9 col-md-10 col-sm-offset-3 col-md-offset-2">-->
<div class="col-sm-9 col-md-10">
    <h4 class="storedpasswords-heading">Stored Accounts</h4>
    <div class="panel-group" id="accordion">
    </div>
</div>

<script>
    $(function () {
        var username;
        var masterKey;
        var passwords;
        var privateSigningKey;
        if (sessionStorage.getItem("password")) {
            $.get("/passwords", function (payload) {
                var data = JSON.parse(payload);
                if (data && data.hasOwnProperty("passwords")
                        && data.hasOwnProperty("salt")
                        && data.hasOwnProperty("privateSigningKey")) {
                    var masterPassword = fromB64(sessionStorage.getItem("password"));
                    masterKey = deriveMasterKey(data.salt, masterPassword);
                    try {
                        passwords = decryptPasswords(masterKey, data.passwords);
                    } catch (err) {
                        console.error(err);
                        window.href = "/logout";
                    }
                    privateSigningKey = parseECDSAPrivateKey(masterPassword, data.privateSigningKey);
                    getAccordions(passwords);

                    $('[data-toggle="tooltip"]').tooltip();
                    $('.copy').each(function (index) {
                        var $copy = $(this);
                        var c = new Clipboard(this, {
                            target: function (trigger) {
                                var v = document.createElement("input");
                                v.className = "temp";
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

                    $(".changePasswordForm").on('submit', function (event) {
                        event.preventDefault();
                        var inputs = $(this).find(':input');
                        var id;
                        var values = {};
                        inputs.each(function () {
                            if (this.name) {
                                if (this.name !== "id") {
                                    values[this.name] = encrypt(masterKey, this.value);
                                } else {
                                    id = this.value;
                                }
                            }
                        });
                        var notes = $(this).find('[name=notes]');
                        values.notes = encrypt(masterKey, notes.val().length > 0 ? notes.val() : null);
                        $.ajax({
                            type: "PUT",
                            url: "/passwords/" + id,
                            data: {
                                changedPassword: JSON.stringify(values)
                            }
                        }).done(defaultErrorHandler);
                    });

                    $(".sharePasswordForm").on('submit', function (event) {
                        event.preventDefault();
                        var inputs = $(this).find(':input');
                        var values = {};
                        var target = $(this).find('#target').val();
                        $.get("/publicEncryptionKey/" + target, {}, function (data) {
                            var response = JSON.parse(data);
                            if (response.success && response.publicEncryptionKey) {
                                var targetPubkey = parseElGamalPublicKey(response.publicEncryptionKey);
                                inputs.each(function () {
                                    if (this.name) {
                                        if (["name", "username", "url", "password", "notes"].indexOf(this.name) !== -1) {
                                            values[this.name] = encrypt(targetPubkey, this.value);
                                        }
                                    }
                                });
                                values["signature"] = sign(privateSigningKey, values);
                                $.post("/shared/" + target, {
                                    sharedPassword: JSON.stringify(values)
                                }, function (data) {
                                    var response = JSON.parse(data);
                                    if (response.success) {
                                        alert("Successfully shared this password with " + target + "!");
                                    } else {
                                        alert(response.error);
                                    }
                                });
                            } else {
                                alert(response.error);
                            }
                        });
                    });

                } else {
                    console.log("Bad payload");
                }
            });
        } else {
            window.location.href = "/logout";
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
                    values[this.name] = encrypt(masterKey, this.value);
                }
            });
            var notes = $(this).find('[name=notes]');
            values.notes = encrypt(masterKey, notes.val().length > 0 ? notes.val() : null);
            $.ajax({
                type: "POST",
                url: "/passwords",
                data: {newPassword: JSON.stringify(values)}
            }).done(defaultErrorHandler);
        });

        $(document).on("click", ".delete", function () {
            var r = confirm("Are you sure you want to delete this Account?");
            if (r == true) {
                var id = $(this).attr("data-id");
                $.ajax({
                    type: "DELETE",
                    url: "/passwords/" + id
                }).done(defaultErrorHandler);
            }
        });

        $(document).on("click", "#genrandom", function () {
            var values = {};
            values.length = 12;
            values["lower"] = true;
            values["upper"] = true;
            values["numbers"] = true;
            values["symbols"] = true;
            $.post('/generator', values, function (data) {
                var response = JSON.parse(data);
                if (response.success) {
                    $("#temprandom").removeClass("hidden");
                    $("#temprandom").text(response.password);
                } else {
                    alert(response.error);
                }
            });
        });

        $(document).on("click", "#plusbtn", function () {
            if (!$("#temprandom").hasClass("hidden")) {
                $("#temprandom").addClass("hidden");
            }
        });
        $('#search').keyup(function () {


            if ($(this).val() == '') {
                $('.panel-group').children().show();
            }
            /*
            var rex = new RegExp($(this).val(), 'i');
            $('.entryName').each(function (i, obj) {
                if (!rex.test($(this).text())) {
                    $(this).parent().parent().parent().hide();
                }
            });
            */
            var rex = new RegExp($(this).val(), 'i');
            $('.panel-group').children().hide();
            $('.entryName').each(function (i, obj) {
                if (rex.test($(this).text())) {
                    $(this).parent().parent().parent().show();
                }
            });
        });
    });
</script>
</#macro>

<@display_page/>