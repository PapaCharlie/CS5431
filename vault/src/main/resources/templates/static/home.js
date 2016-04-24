/**
 * Created by papacharlie on 2016-04-13.
 */

function getAccordions(passwords) {
    passwords.forEach(function (entry) {
        //$("#accordion").append($('<div></div>').addClass("panel panel-default"));

        var pd = $('<div/>',{
            'class': 'panel panel-default'
        });
        var ph = $('<div/>',{
            'class': 'panel-heading'
        }).appendTo(pd);
        var title = $('<h4/>',{
            'class': 'panel-title'
        }).appendTo(ph);
        var link = $('<a/>',{
            'href': '#'+entry.id,
            'data-toggle': 'collapse',
            'data-parent': '#accordion',
            'text': entry.name
        }).appendTo(title);
        var delbtn = $('<button/>',{
            'class': 'delete btn btn-danger btn-xs',
            'data-id': entry.id,
            'style': 'float: right',
            'aria-hidden': 'true',
            'text': 'Delete'
        }).appendTo(title);

        var pc = $('<div/>',{
            'id': entry.id,
            'class': 'panel-collapse collapse'
        }).appendTo(pd);
        var pb = $('<div/>',{
            'class': 'panel-body'
        }).appendTo(pc);
        var row1 = $('<div/>',{
            'class': 'row'
        }).appendTo(pb);
        var url = $('<div/>',{
            //'id': entry.id,
            'class': 'col-sm-4 col-md-4',
            'text': 'URL: '+entry.url
        }).appendTo(row1);
        var row2 = $('<div/>',{
            'class': 'row'
        }).appendTo(pb);
        var username = $('<div/>',{
            'class': 'col-sm-4 col-md-4',
            'text': 'Username: '+entry.username
        }).appendTo(row2);
        var passdiv = $('<div/>',{
            //'id': entry.name,
            'class': 'col-sm-4 col-md-4',
            'text': 'Password: '
        }).appendTo(row2);
        var passinput = $('<input/>',{
            'id': entry.id+'copy',
            'type': 'password',
            'readonly': '',
            'value': entry.password
        }).appendTo(passdiv);
        var copybtn = $('<button/>',{
            'class': 'copy btn btn-default btn-sm',
            'data-toggle': 'tooltip',
            'title': 'Copied!',
            'data-placement': 'bottom',
            'data-trigger': 'click',
            'data-clipboard-action': 'copy',
            'data-clipboard-target': '#'+entry.id+'copy',
            'text': 'Copy'
        }).appendTo(passdiv);
        var revealbtn = $('<button/>',{
            'class': 'reveal btn btn-default btn-sm',
            'id': entry.id+'reveal',
            'text': 'Reveal'
        }).appendTo(passdiv);
        var editbtn = $('<button/>',{
            'type': 'button',
            'class': 'btn btn-warning',
            'data-toggle': 'modal',
            'data-target': '#'+entry.id+'modal',
            'text': 'Edit Account Info'
        }).appendTo(row2);
        var modalstart = $('<div/>',{
            'id': entry.id+'modal',
            'class': 'modal fade',
            'role': 'dialog'
        }).appendTo(row2);

        var md = $("<div class='modal-dialog'></div>").appendTo(modalstart);

        var mc = $("<div class='modal-content'></div>").appendTo(md);

        var modalheader = $("<div class='modal-header'>" +
            "<button type='button' class='close' data-dismiss='modal'>&times;</button>" +
            "<h4 class='modal-title'>Edit Account Details</h4>" +
            "</div>").appendTo(mc);

        var mb = $("<div class='modal-body'></div>").appendTo(mc);

        var form = $("<form class='changePasswordForm'></form>").appendTo(mb);

        var input1 = $('<input/>',{
            'type': 'hidden',
            'name': 'id',
            'class': 'form-control',
            'value': entry.id
        }).appendTo(form);
        var changename = $('<input/>',{
            'type': 'text',
            'name': 'name',
            'class': 'form-control',
            'value': entry.name,
            'required': 'true'
        }).appendTo(form);
        var changeurl = $('<input/>',{
            'type': 'url',
            'name': 'url',
            'class': 'form-control',
            'value': entry.url,
            'required': 'true'
        }).appendTo(form);
        var changeusername = $('<input/>',{
            'type': 'text',
            'name': 'username',
            'class': 'form-control',
            'value': entry.username,
            'required': 'true'
        }).appendTo(form);
        var changepass = $('<input/>',{
            'type': 'text',
            'name': 'password',
            'class': 'form-control',
            'value': entry.password,
            'required': 'true'
        }).appendTo(form);
        var changeurl = $('<button/>',{
            'class': 'btn btn-primary',
            'type': 'submit',
            'text': 'Save new password'
        }).appendTo(form);

        var modalfooter = $("<div class='modal-footer'>" +
            "<button type='button' class='btn btn-default' data-dismiss='modal'>Close</button>" +
            "</div>").appendTo(mc);

        $('#accordion').append(pd);


    });
}

