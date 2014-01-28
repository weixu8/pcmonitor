function getScreenshots(hostId, begin, end)
{
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
			var ids = $.parseJSON(result.ids);
			var idsToTime = $.parseJSON(result.idsToTime);
			for (var i = 0; i < ids.length; i++) {
				var id = ids[i];
				var url = "/screenshot/" + hostId + "/" + id;
				$('#screenshots').append(
				'<div class="screenhost">' + 
				'<p class="screenTime">' + idsToTime[id] + '</p>' + 
				'<img class="screenPic" src=' + url + ' alt="alt text">' + 
				'</div>'
				);					
			}
		}
	});
}
updateScreenshots();
setInterval(updateScreenshots, 30000);