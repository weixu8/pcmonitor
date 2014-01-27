function getScreenshots(hostId, begin, end)
{
	console.log("hostId=" + hostId);
	var req = $.ajax({
		url : "/host/" + hostId + "/screenshots/" + begin + "/" + end, 
	  	data : "",
	  	contentType : "application/json;charset=utf-8",
	  	type : "GET"});

	return req;
}

function updateScreenshots()
{
	$('#screenshots').empty();
	var hostId = $('#hostId').text();
	var req = getScreenshots(hostId, 0, 20);
	req.done(function( data ) {
		var result = $.parseJSON(data);
		if (result.error == 0) {
			var ids = $.parseJSON(result.picIds);
			for (var i = 0; i < ids.length; i++) {
				var url = "/screenshot/" + hostId + "/" + ids[i];
				$('#screenshots').append('<img src=' + url + ' alt="alt text">');
				
			}
		}
	});
}
updateScreenshots();
setInterval(updateScreenshots, 30000);