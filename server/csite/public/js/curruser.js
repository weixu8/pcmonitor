function currUser()
{
	var req = $.ajax({
		url : "/currUser", 
	  	data : "",
	  	contentType : "application/json;charset=utf-8",
	  	type : "GET"});
	 
	return req;
}