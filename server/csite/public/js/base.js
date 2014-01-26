var req = currUser();
req.done(function( data ) {
	user = $.parseJSON(data);
	if (user.uid != -1) {
		$('#navbarList').empty();
        $('#navbarList').append('<li><a href="/profile"><strong>' + user.username + '</strong></a></li>');
		$('#navbarList').append('<li><a id="loginLink" href="/login">Log In</a></li>');
		$('#navbarList').append('<li><a href="/join">Join</a></li>');
        $('#navbarList').append('<li><a href="/about">About</a></li>');
		$('#loginLink').attr('href', '/logout');
		$('#loginLink').text('Log out');
		
	} else {
		$('#navbarList').empty();
		$('#navbarList').append('<li><a id="loginLink" href="/login">Log In</a></li>');
		$('#navbarList').append('<li><a href="/join">Join</a></li>');
        $('#navbarList').append('<li><a href="/about">About</a></li>');        
		$('#loginLink').attr('href', '/login');
		$('#loginLink').text('Log in');
	}
});
