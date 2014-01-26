// Attach a submit handler to the form
$( "#signinForm" ).submit(function( event ) {
 
  // Stop form from submitting normally
  event.preventDefault();
  
  // Get some values from elements on the page:
  var $form = $( this ),
    email_v = $form.find( "input[name='email']" ).val(),
    pass_v = $form.find( "input[name='pass']" ).val(),
    url_v = $form.attr( "action" );
  
  // Send the data using post
  var posting = $.ajax({
  url : url_v, 
  data : JSON.stringify({ email: email_v, pass : pass_v }),
  contentType : "application/json;charset=utf-8",
  type : "POST"});
 
  // Put the results in a div
  posting.done(function( data ) {
  	var obj = $.parseJSON(data);
  	if (obj.error != 0) {
		$("#result" ).empty().append("<p> ERROR=" + obj.error + " desc=" + obj.errorS + "</p>");
	} else {
		$(location).attr('href','/profile');
	}
  });
});