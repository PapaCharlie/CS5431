
$(function() {
    $( "#datepicker1" ).datepicker();
    $('#datepicker2').datepicker();
});

function is_in_timerange(startDate, endDate, dateText){
    var temp = dateText.split("T");
    var res = temp[0].split("-");
    var year = parseInt(res[0]);
    var month = parseInt(res[1]) - 1;
    var day = parseInt(res[2]);
    var dateObj = new Date(year, month, day);
    return (dateObj.getTime() >= startDate.getTime() && dateObj.getTime() <= endDate.getTime());
}


$(document).on('click','.dropdown-menu li a',function(){
    var logType = $(this).text();
    $('#filter').val(logType);
});


$(document).on('click','#searchAll', function(){
    var startDate = ($('#datepicker1').datepicker("getDate"));
    var endDate = ($('#datepicker2').datepicker("getDate"));
    var logType = $('#filter').val();
    var message = $('#message').val();
    var ip = $('#ipText').val();
    if( startDate != null && endDate != null && endDate >= startDate){
        $('.date').each(function(i, obj){
            if(!is_in_timerange(startDate, endDate, $(this).text()) && $(this).parent().is(':visible')){
                $(this).parent().hide();
            }
        });
    }
    if(logType != ''){
        var rex = new RegExp(logType, 'i');
        $('.logType').each(function(i, obj){
            if(!(rex.test($(this).text()))){
                $(this).parent().hide();
            }
        });
    }
    if(message!= ''){
        var rex = new RegExp(message, 'i');
        $('.search').each(function(i, obj){
            if(!(rex.test($(this).text()))){
                $(this).parent().hide();
            }
        });
    }
    if(ip!= ''){
        var rex = new RegExp(ip, 'i');
        $('.ip').each(function(i, obj){
            if(!(rex.test($(this).text()))){
                $(this).parent().hide();
            }
        });
    }

});

$(document).on('click', '#clear', function(){
    $('#filter').val('');
    $('#datepicker1').val('')
    $('#datepicker2').val('');
    $('#ipText').val('');
    $('#message').val('');
    $('.filterable').show();
});


