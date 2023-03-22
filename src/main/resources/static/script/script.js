
var logout = function () {
    $.post("/leave/authentication", function () {
        Cookies.set('XSRF-TOKEN', '');
        $("#user").html('');
        $(".unauthenticated").show();
        $(".authenticated").hide();
    });
    return true;
};

(function () {
    var span = $("#user").text();
    var errorSpan = $(".error");
    var errorMsg = errorSpan.text();
    console.log("span text value : " + span);
    console.log("error message is : " + errorMsg);
    if(span === undefined || span.length === 0){
        $(".unauthenticated").show();
        $(".authenticated").hide();
        errorFunc(errorSpan, errorMsg);
    }else {
        $(".unauthenticated").hide();
        $(".authenticated").show();
        errorFunc(errorSpan, errorMsg);
    }
})();

$.ajaxSetup({
    beforeSend : function(xhr, settings) {
        if (settings.type === 'POST' || settings.type === 'PUT'
            || settings.type === 'DELETE') {
            if (!(/^http:.*/.test(settings.url) || /^https:.*/
                .test(settings.url))) {
                // Only send the token to relative URLs i.e. locally.
                xhr.setRequestHeader("X-XSRF-TOKEN",
                    Cookies.get('XSRF-TOKEN'));
            }
        }
    }
});

function errorFunc (errSpan, errMsg) {
    if(errMsg === undefined || errMsg.length === 0) {
        errSpan.hide();
    }else {
        errSpan.show();
    }
};