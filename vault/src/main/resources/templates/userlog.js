$(document).ready(function () {

    (function ($) {

        $('#filter').keyup(function () {

            var rex = new RegExp($(this).val(), 'i');
            $('.logtable tr').hide();
            $('.logtable tr').filter(function () {
                return rex.test($(this).text());
            }).show();

        })

    }(jQuery));

});

$(document).on('click', '.dropdown-menu li a',function(){

    //alert($(this).text());
    $('#filter').val(" ");
    if($(this).text() == "Display All"){
        $('.logtable tr').show();
    } else {
        var rex = new RegExp($(this).text(), 'i');
        $('.logtable tr').hide();
        $('.logtable tr').filter(function () {
            return rex.test($(this).text());
        }).show();
    }
});