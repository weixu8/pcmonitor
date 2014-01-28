var keyEvStart = 0;

function getKeybrdEvents(hostId, begin, end)
{
	var req = $.ajax({
		url : "/host/" + hostId + "/getKbEvents/" + begin + "/" + end, 
	  	data : "",
	  	contentType : "application/json;charset=utf-8",
	  	type : "GET"});

	return req;
}

function updateKeybrdEvents()
{
	var start = keyEvStart;
	var limit = 1000;
	var hostId = $('#hostId').text();
	
	var req = getKeybrdEvents(hostId, start, start+limit);
	req.done(function( data ) {
		var result = $.parseJSON(data);
		if (result.error == 0) {		
			var events = $.parseJSON(result.events);		
			var html = '<div class="kbevent"><p class="time">' + $.parseJSON(events[0]).sysTime;
			html+= ' to ' + $.parseJSON(events[events.length-1]).sysTime + '</p>';
			html+= '<p>';
			for (var i = 0; i < events.length; i++) {
				var event = $.parseJSON(events[i]);
				if (parseInt(event.keyUp) > 0) {
					if (event.buffer.length > 1)
						html+= ' ' + event.buffer + ' ';
					else
						html+= event.buffer;
				}
			}
			html+= '</p></div>';
			$('#kbevents').append(html);
			keyEvStart+= events.length;
		}
	});
}


updateKeybrdEvents();
setInterval(updateKeybrdEvents, 1000);