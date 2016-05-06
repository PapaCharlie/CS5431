<#include "vault.ftl">

<#macro page_body>
<div class="col-sm-9 col-md-10">

</div>


<div class="col-sm-9 col-md-10">
    <p>
    <div class="input-group col-xs-6 col-sm-3">
    <div class="input-group-addon">
        <span>Search </span>
    </div>
        <input id="search" type="text" class="form-control" placeholder="Type username here...">
    </div>
    </p>
    <h4 class="storedpasswords-heading">Shared Passwords</h4>

    <div class="panel-group" id="accordion">
    </div>
</div>

<script>
    $(function () {
        var masterKey;
        var sharedPasswords = [];
        var privateEncryptionKey;
        if (sessionStorage.getItem("password")) {
            $.get("/shared", function (payload) {
                var data = JSON.parse(payload);
                if (data && data.hasOwnProperty("sharedPasswords")
                        && data.hasOwnProperty("privateEncryptionKey")
                        && data.hasOwnProperty("salt")) {
                    if (data.sharedPasswords.length > 0) {
                        var masterPassword = fromB64(sessionStorage.getItem("password"));
                        masterKey = deriveMasterKey(data.salt, masterPassword);
                        privateEncryptionKey = parseElGamalPrivateKey(masterPassword, data.privateEncryptionKey);
                        data.sharedPasswords.forEach(function (password) {
                            var signature = password.signature;
                            var sharerPublicSigningKey = parseECDSAPublicKey(password.sharerPublicSigningKey);
                            delete password.sharerPublicSigningKey;
                            delete password.signature;
                            if (verifySignature(sharerPublicSigningKey, password, signature)) {
                                console.log("Signature verified!");
                                var signedPassword = {};
                                for (var prop in password) {
                                    if (password.hasOwnProperty(prop)) {
                                        if (["name", "username", "url", "password", "notes"].indexOf(prop) !== -1) {
                                            signedPassword[prop] = decrypt(privateEncryptionKey, password[prop]);
                                        } else {
                                            signedPassword[prop] = password[prop];
                                        }
                                    }
                                }
                                sharedPasswords.push(signedPassword)
                            } else {
                                console.error("Rejecting password from " + password.sharer + " based on signature.");
                                $.ajax({
                                    type: "DELETE",
                                    url: "/shared/" + password.id
                                }).done(defaultErrorHandler);
                            }
                        });
                        getSharedAccordions(sharedPasswords);

                        $(document).on("click", ".save", function () {
                            var r = confirm("Are you sure you want to accept this password?");
                            if (r == true) {
                                var id = $(this).attr("data-id");
                                var filtered = sharedPasswords.filter(function (password) {
                                    return password.id === id
                                });
                                if (filtered.length > 0) {
                                    var password = filtered[0];
                                    var values = {};
                                    for (var prop in password) {
                                        if (password.hasOwnProperty(prop) && ["name", "username", "url", "password", "notes"].indexOf(prop) !== -1) {
                                            values[prop] = encrypt(masterKey, password[prop]);
                                        }
                                    }
                                    $.ajax({
                                        type: "PUT",
                                        url: "/shared/" + id,
                                        data: {
                                            acceptedPassword: JSON.stringify(values)
                                        }
                                    }).done(defaultErrorHandler);
                                } else {
                                    console.error("Could not find shared password with id: " + id);
                                }
                            }
                        });

                        $(document).on("click", ".delete", function () {
                            var r = confirm("Are you sure you want to reject this password?");
                            if (r == true) {
                                var id = $(this).attr("data-id");
                                $.ajax({
                                    type: "DELETE",
                                    url: "/shared/" + id
                                }).done(defaultErrorHandler);
                            }
                        });

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

                    } else {
                        getSharedAccordions([]);
                    }
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

    });

        $('#search').keyup(function () {
            if ($(this).val() == '') {
                $('.panel-group').children().show();
            }
            var rex = new RegExp($(this).val(), 'i');
            $('.panel-group').children().hide();
            $('.sharedUser').each(function(i, obj) {
                var text = $(this).text();
                var temp = text.split("by");
                var user = temp[1];
                if (rex.test(user)) {
                    $(this).parent().parent().parent().show();
                }
            });
        });
</script>
</#macro>

<@display_page/>