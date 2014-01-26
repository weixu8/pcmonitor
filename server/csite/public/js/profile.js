var req = currUser();
req.done(function( data ) {
	user = $.parseJSON(data);
	if (user.uid != -1) {
		$('#profileUserName').text(user.username);
		$('#profileUID').text(user.uid);
		$('#profileSession').text(user.session);
		$('#profileClientId').text(user.clientId);
		$('#profileAuthId').text(user.authId);	
	}
});