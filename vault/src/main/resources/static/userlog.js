$(document).ready(function () {

    (function ($) {

        $('#filter').keyup(function () {

            var rex = new RegExp($(this).val(), 'i');
            $('.filterable').hide();
            $('.search').each(function(i, obj){
                if(rex.test($(this).text())) {
                    //console.log(rex.test($(this).text()));
                    $(this).parent().show();
                }

            })

           /*
            $('.filterable').hide();
            $('.filterable').filter(function () {
                return rex.test($(this).text());
            }).show();
           */
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
        $('.filterable').hide();
        $('.filterable').filter(function () {
            return rex.test($(this).text());
        }).show();
    }
});