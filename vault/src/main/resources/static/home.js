/**
 * Created by papacharlie on 2016-04-13.
 */


function getSharedAccordions(sharedPasswords) {
    if (sharedPasswords.length > 0) {
        var p =
            sharedPasswords.sort(function(a,b){
                return a.name.localeCompare(b.name);
            });
        p.forEach(function (entry) {
            var pd = $('<div/>', {
                'class': 'panel panel-default'
            });
            var ph = $('<div/>', {
                'class': 'panel-heading'
            }).appendTo(pd);
            var title = $('<h4/>', {
                'class': 'panel-title'
            }).appendTo(ph);
            var link = $('<a/>', {
                'href': '#' + entry.id,
                'data-toggle': 'collapse',
                'data-parent': '#accordion',
                'text': entry.name
            }).appendTo(title);
            var delbtn = $('<button/>', {
                'class': 'Reject btn btn-danger btn-xs',
                'data-id': entry.id,
                'style': 'float: right',
                'aria-hidden': 'true',
                'text': 'Reject'
            }).appendTo(title);
            var savebtn = $('<button/>', {
                'class': 'save btn btn-success btn-xs',
                'style': 'float: right; margin-right: 2px',
                'data-id': entry.id,
                'aria-hidden': 'true',
                'text': 'Save',
                'type': 'button'
            }).appendTo(title);

            var pc = $('<div/>', {
                'id': entry.id,
                'class': 'panel-collapse collapse'
            }).appendTo(pd);
            var pb = $('<div/>', {
                'class': 'panel-body'
            }).appendTo(pc);
            //var row1 = $('<div/>', {
            //    'class': 'row'
            //}).appendTo(pb);
            var url = $('<div/>', {
                //'id': entry.id,
                //'class': 'col-sm-4 col-md-4',
                'class': 'accordionField'
                //'text': 'URL: '// + entry.url
            }).appendTo(pb); //row1
            var boldurl = $('<b/>', {
                'text': 'URL: '
            }).appendTo(url);
            var urllink = $('<a/>', {
                'href': entry.url,
                'target': '_blank',
                'text': entry.url
            }).appendTo(url);
            //var row2 = $('<div/>', {
            //    'class': 'row'
            //}).appendTo(pb);
            var username = $('<div/>', {
                //'class': 'col-sm-4 col-md-4',
                'class': 'accordionField',
                'text': entry.username
            }).appendTo(pb); //row2
            var boldusername = $('<b/>', {
                //'class': 'col-sm-4 col-md-4',
                'text': 'Username: '
            }).prependTo(username); //row2

            var passdiv = $('<div/>', {
                //'id': entry.name,
                //'class': 'col-sm-4 col-md-4',
                'class': 'accordionField'
                //'text': 'Password: '
            }).appendTo(pb); //row2
            var boldpass = $('<b/>', {
                //'id': entry.name,
                //'class': 'col-sm-4 col-md-4',
                'text': 'Password: '
            }).prependTo(passdiv); //row2
            var passinput = $('<input/>', {
                'id': entry.id + 'copy',
                'type': 'password',
                'readonly': '',
                'value': entry.password
            }).appendTo(passdiv);
            var copybtn = $('<button/>', {
                'class': 'copy btn btn-default btn-sm',
                'data-toggle': 'tooltip',
                'title': 'Copied!',
                'data-placement': 'bottom',
                'data-trigger': 'click',
                'data-clipboard-action': 'copy',
                'data-clipboard-target': '#' + entry.id + 'copy',
                'text': 'Copy'
            }).appendTo(passdiv);
            var revealbtn = $('<button/>', {
                'class': 'reveal btn btn-default btn-sm',
                'id': entry.id + 'reveal',
                'text': 'Reveal'
            }).appendTo(passdiv);

            var row3 = $('<div/>', {
                'class': 'row'
            }).appendTo(pb);
            var notescontainer = $('<div/>', {
                'class': 'col-sm-4 col-md-4'
            }).appendTo(row3);
            var label = $('<label/>', {
                //'class': 'col-sm-4 col-md-4',
                'text': 'Notes',
                'for': 'notes'
            }).appendTo(notescontainer);
            var notes = $('<div/>', {
                //'class': 'col-sm-4 col-md-4',
                'id': 'notes',
                'text': entry.notes ? entry.notes : ""
            }).appendTo(notescontainer);

            $('#accordion').append(pd);

        });
    } else {
        $('#accordion').text("No shared passwords!");
    }
}

function getAccordions(passwords) {
    if (passwords.length > 0) {
        var p =
        passwords.sort(function(a,b){
            return a.name.localeCompare(b.name);
        });
        p.forEach(function (entry) {
            var pd = $('<div/>', {
                'class': 'panel panel-default'
            });
            var ph = $('<div/>', {
                'class': 'panel-heading'
            }).appendTo(pd);
            var title = $('<h4/>', {
                'class': 'panel-title'
            }).appendTo(ph);
            var link = $('<a/>', {
                'href': '#' + entry.id,
                'data-toggle': 'collapse',
                'data-parent': '#accordion',
                'text': entry.name
            }).appendTo(title);
            var delbtn = $('<button/>', {
                'class': 'delete btn btn-danger btn-xs',
                'data-id': entry.id,
                'style': 'float: right',
                'aria-hidden': 'true',
                'text': 'Delete'
            }).appendTo(title);
            var editsmall = $('<button/>', {
                'class': 'edit btn btn-warning btn-xs',
                'style': 'float: right; margin-right: 2px',
                'aria-hidden': 'true',
                'text': 'Edit',
                'type': 'button',
                'data-toggle': 'modal',
                'data-target': '#' + entry.id + 'modal'
            }).appendTo(title);
            var sharesmall = $('<button/>', {
                'class': 'share btn btn-primary btn-xs',
                'style': 'float: right; margin-right: 2px',
                'aria-hidden': 'true',
                'text': 'Share',
                'type': 'button',
                'data-toggle': 'modal',
                'data-target': '#' + entry.id + 'sharemodal'
            }).appendTo(title);

            var pc = $('<div/>', {
                'id': entry.id,
                'class': 'panel-collapse collapse'
            }).appendTo(pd);
            var pb = $('<div/>', {
                'class': 'panel-body'
            }).appendTo(pc);
            //var row1 = $('<div/>', {
            //    'class': 'row'
            //}).appendTo(pb);
            var url = $('<div/>', {
                //'id': entry.id,
                //'class': 'col-sm-4 col-md-4',
                'class': 'accordionField'
                //'text': 'URL: '// + entry.url
            }).appendTo(pb); //row1
            var boldurl = $('<b/>', {
                'text': 'URL: '
            }).appendTo(url);
            var urllink = $('<a/>', {
                'href': entry.url,
                'target': '_blank',
                'text': entry.url
            }).appendTo(url);
            //var row2 = $('<div/>', {
            //    'class': 'row'
            //}).appendTo(pb);
            var username = $('<div/>', {
                //'class': 'col-sm-4 col-md-4',
                'class': 'accordionField',
                'text': entry.username
            }).appendTo(pb); //row2
            var boldusername = $('<b/>', {
                //'class': 'col-sm-4 col-md-4',
                'text': 'Username: '
            }).prependTo(username); //row2

            var passdiv = $('<div/>', {
                //'id': entry.name,
                //'class': 'col-sm-4 col-md-4',
                'class': 'accordionField'
                //'text': 'Password: '
            }).appendTo(pb); //row2
            var boldpass = $('<b/>', {
                //'id': entry.name,
                //'class': 'col-sm-4 col-md-4',
                'text': 'Password: '
            }).prependTo(passdiv); //row2
            var passinput = $('<input/>', {
                'id': entry.id + 'copy',
                'type': 'password',
                'readonly': '',
                'value': entry.password
            }).appendTo(passdiv);
            var copybtn = $('<button/>', {
                'class': 'copy btn btn-default btn-sm',
                'data-toggle': 'tooltip',
                'title': 'Copied!',
                'data-placement': 'bottom',
                'data-trigger': 'click',
                'data-clipboard-action': 'copy',
                'data-clipboard-target': '#' + entry.id + 'copy',
                'text': 'Copy'
            }).appendTo(passdiv);
            var revealbtn = $('<button/>', {
                'class': 'reveal btn btn-default btn-sm',
                'id': entry.id + 'reveal',
                'text': 'Reveal'
            }).appendTo(passdiv);
            //var editbtn = $('<button/>', {
            //    'type': 'button',
            //    'class': 'btn btn-warning',
            //    'data-toggle': 'modal',
            //    'data-target': '#' + entry.id + 'modal',
            //    'text': 'Edit Account Info'
            //}).appendTo(row2);
            var modalstart = $('<div/>', {
                'id': entry.id + 'modal',
                'class': 'modal fade',
                'role': 'dialog'
            }).appendTo(title); //row2

            var md = $("<div class='modal-dialog'></div>").appendTo(modalstart);

            var mc = $("<div class='modal-content'></div>").appendTo(md);

            var modalheader = $("<div class='modal-header'>" +
                "<button type='button' class='close' data-dismiss='modal'>&times;</button>" +
                "<h4 class='modal-title'>Edit Account Details</h4>" +
                "</div>").appendTo(mc);

            var mb = $("<div class='modal-body'></div>").appendTo(mc);

            var form = $("<form class='changePasswordForm'></form>").appendTo(mb);

            var input1 = $('<input/>', {
                'type': 'hidden',
                'name': 'id',
                'class': 'form-control',
                'value': entry.id
            }).appendTo(form);
            var changename = $('<input/>', {
                'type': 'text',
                'name': 'name',
                'class': 'form-control',
                'maxlength': '500',
                'value': entry.name,
                'required': 'true'
            }).appendTo(form);
            var changeurl = $('<input/>', {
                'type': 'url',
                'name': 'url',
                'class': 'form-control',
                'maxlength': '500',
                'value': entry.url,
                'required': 'true'
            }).appendTo(form);
            var changeusername = $('<input/>', {
                'type': 'text',
                'name': 'username',
                'class': 'form-control',
                'maxlength': '500',
                'value': entry.username,
                'required': 'true'
            }).appendTo(form);
            var changepass = $('<input/>', {
                'type': 'text',
                'name': 'password',
                'class': 'form-control',
                'maxlength': '500',
                'value': entry.password,
                'required': 'true'
            }).appendTo(form);
            var changenotes = $('<textarea/>', {
                'name': 'notes',
                'class': 'form-control',
                'maxlength': '1000',
                'text': 'put current secure notes here'
            }).appendTo(form);
            var changeform = $('<button/>', {
                'class': 'btn btn-primary',
                'type': 'submit',
                'text': 'Save changes'
            }).appendTo(form);

            var modalfooter = $("<div class='modal-footer'>" +
                "<button type='button' class='btn btn-default' data-dismiss='modal'>Close</button>" +
                "</div>").appendTo(mc);

            var sharemodalstart = $('<div/>', {
                'id': entry.id + 'sharemodal',
                'class': 'modal fade',
                'role': 'dialog'
            }).appendTo(title); //row2

            var sharemd = $("<div class='modal-dialog'></div>").appendTo(sharemodalstart);

            var sharemc = $("<div class='modal-content'></div>").appendTo(sharemd);

            var sharemodalheader = $("<div class='modal-header'>" +
                "<button type='button' class='close' data-dismiss='modal'>&times;</button>" +
                "<h4 class='modal-title'>Share Password</h4>" +
                "</div>").appendTo(sharemc);

            var sharemb = $("<div class='modal-body'></div>").appendTo(sharemc);

            $("<h5>Please enter the username of the user you want to send this password to:</h5>").appendTo(sharemb);

            var shareform = $("<form class='sharePasswordForm'></form>").appendTo(sharemb);

            var shareinput1 = $('<input/>', {
                'type': 'hidden',
                'name': 'id',
                'class': 'form-control',
                'value': entry.id
            }).appendTo(shareform);
            var sharetarget = $('<input/>', {
                'type': 'text',
                'name': 'target',
                'id': 'target',
                'class': 'form-control',
                'placeholder': 'Username',
                'value': '',
                'required': 'true'
            }).appendTo(shareform);
            var sharechangename = $('<input/>', {
                'type': 'hidden',
                'name': 'name',
                'class': 'form-control',
                'value': entry.name,
                'required': 'true'
            }).appendTo(shareform);
            var sharechangeurl = $('<input/>', {
                'type': 'hidden',
                'name': 'url',
                'class': 'form-control',
                'value': entry.url,
                'required': 'true'
            }).appendTo(shareform);
            var sharechangeusername = $('<input/>', {
                'type': 'hidden',
                'name': 'username',
                'class': 'form-control',
                'value': entry.username,
                'required': 'true'
            }).appendTo(shareform);
            var sharechangepass = $('<input/>', {
                'type': 'hidden',
                'name': 'password',
                'class': 'form-control',
                'value': entry.password,
                'required': 'true'
            }).appendTo(shareform);
            var sharechangeform = $('<button/>', {
                'class': 'btn btn-primary',
                'type': 'submit',
                'text': 'Share'
            }).appendTo(shareform);

            var sharemodalfooter = $("<div class='modal-footer'>" +
                "<button type='button' class='btn btn-default' data-dismiss='modal'>Close</button>" +
                "</div>").appendTo(sharemc);

            var row3 = $('<div/>', {
                'class': 'row'
            }).appendTo(pb);
            var notescontainer = $('<div/>', {
                'class': 'col-sm-4 col-md-4'
            }).appendTo(row3);
            var label = $('<label/>', {
                //'class': 'col-sm-4 col-md-4',
                'text': 'Notes',
                'for': 'notes'
            }).appendTo(notescontainer);
            var notes = $('<div/>', {
                //'class': 'col-sm-4 col-md-4',
                'id': 'notes',
                'text': entry.notes ? entry.notes : ""
            }).appendTo(notescontainer);

            $('#accordion').append(pd);

        });
    } else {
        $('#accordion').text("No stored passwords!");
    }
}

function defaultErrorHandler(data, location) {
    var response = JSON.parse(data);
    if (response.success) {
        window.location.reload();
    } else {
        alert(response.error);
    }
}