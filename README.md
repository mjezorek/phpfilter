### License
 Copyright (c) 2013 Matt Jezorek 
 This code is released under the public domain, feel free to use as you wish
 for whatever you wish, it would be cool if you let me know your using it but idgaf.

### About
 This class will help your PHP applications deal with CSRF and XSS bugs. 
 Make sure this is the first thing that runs in your application. 

### Features
 CSRF mitigation & detection
 CSRF alerting & logging of forms that do not have any protections (excludes GET)
 XSS Protection on all POST/GET parameters
 Securely disable filtering for fields of your choice. 

### Example

	<?php
	session_start();
	$sr = new SecureRequests();
	$sr->safeRequest();
	$val = '';
	if(isset($_POST['test_field'])) {
		$val = $_POST['test_field'];
	}
	?>
	<form method="POST" action="/omgzors">
	<?php $sr->protectForm('test_post', ''); ?>
	<input type="text" value="<?php echo $val;?>" name="test_field" />
	<input type="submit" value="Go" />
	</form>


### Disclaimer
None of this shit works, but it might be cool to look at, the code is ugly as well and idgaf.
