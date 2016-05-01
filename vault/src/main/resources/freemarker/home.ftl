<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10">

    <span class="addicon glyphicon glyphicon-plus" data-toggle="collapse" data-target="#newPasswordForm" aria-hidden="true"></span>

    <form class="form-signin collapse newpass" id="newPasswordForm">
        <h4  class="form-signin-heading">New Password</h4>
        <input type="text" name="name" class="form-control" placeholder="Website Name" required>
        <input type="url" name="url" class="form-control" placeholder="URL" required>
        <input type="text" name="username" id="username" class="form-control" placeholder="Account username" required>
        <input type="password" name="password" id="inputPassword" class="form-control" placeholder="Password" required>
        <textarea form="newPasswordForm" name="notes" class="form-control" placeholder="Secure Notes (Optional)"></textarea>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Create New Password</button>
    </form>
</div>

<#--<div class="col-sm-9 col-md-10 col-sm-offset-3 col-md-offset-2">-->
<div class="col-sm-9 col-md-10">
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
                    key = deriveMasterKey(data.salt, sessionStorage.getItem("password"));
                    passwords = decryptPasswords(key, data.passwords);
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
                        console.log("hmm?{");
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
                        $.ajax({
                            type: "PUT",
                            url: "/passwords/" + id,
                            data: {
                                id: id,
                                changedPassword: JSON.stringify(values)
                            }
                        }).done(defaultErrorHandler);
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
                    values[this.name] = encrypt(key, this.value);
                }
            });
            $.ajax({
                type: "POST",
                url: "/passwords",
                data: {newPassword: JSON.stringify(values)}
            }).done(defaultErrorHandler);
        });



    });


    $(document).on("click", ".delete", function () {
        var r = confirm("Are you sure you want to delete this Account?");
        if (r == true) {
//            $(this).closest("div.panel-default").remove();
            var id = $(this).attr("data-id");
            $.ajax({
                type: "DELETE",
                url: "/passwords/" + id,
                data: {id: id}
            }).done(defaultErrorHandler);
        }
    });

</script>
</#macro>

<@display_page/>