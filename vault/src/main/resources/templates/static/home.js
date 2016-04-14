/**
 * Created by papacharlie on 2016-04-13.
 */

function getAccordions(passwords) {
    passwords.forEach(function (entry) {
        $("#accordion").append(
            "<div class='panel panel-default'>" +
            "<div class='panel-heading'>" +
            "<h4 class='panel-title'>" +
            "<a data-toggle='collapse' data-parent='#accordion' href=#" + entry.id + ">" +
            entry.name + "</a>" +
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
            "<button type='button' class='btn btn-warning' data-toggle='modal' data-target='#" + entry.id + "modal'>Change password</button>" +
            "<div id='" + entry.id + "modal' class='modal fade' role='dialog'>" +
            "<div class='modal-dialog'>" +
                <!-- Modal content-->
            "<div class='modal-content'>" +
            "<div class='modal-header'>" +
            "<button type='button' class='close' data-dismiss='modal'>&times;</button>" +
            "<h4 class='modal-title'>Set New Password for " + entry.name + "</h4>" +
            "</div>" +
            "<div class='modal-body'>" +
            "<form method='post' action='/vault/changepassword'>" +
            "<input required type='text' class='form-control' placeholder='New Password'>" +
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