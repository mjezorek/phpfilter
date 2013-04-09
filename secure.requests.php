<?php
/**
* Copyright (c) 2013 Matt Jezorek 
* This code is released under the public domain, feel free to use as you wish
* for whatever you wish, it would be cool if you let me know your using it but idgaf.
* 
* This class will help your PHP applications deal with CSRF and XSS bugs. 
* Make sure this is the first thing that runs in your application. 
*
* Features:
* CSRF mitigation & detection
* CSRF alerting & logging of forms that do not have any protections (excludes GET)
* XSS Protection on all POST/GET parameters
* Securely disable filtering for fields of your choice. 
*/
class SecureRequests {
	/**
	* You should change this key, yes we could use a key in a file or whatever but this will work as long as it is changed 
	*/
	private $securityKey = "Q()*jdsa895yh7346*u9AUTHIG83295uaiudsoap432968uy679()*&5a}";
	// valid actions for CSRF violations are none, log, block, log_block
	private $csrfVolationAction = 'log';
	// log file we want to log too. 
	private $securityLogFile = 'csrf.log';
	/**
	* Construct
	*/
	public function __construct() {
	}

	/**
	* protectForm
	* This function is used to output the protected fields of the form. These fields
	* work for CSRF protection and XSS filter avoidance. You may pass a list of form
	* fields that you don't want to filter to this method.
	* This method should be used in each form you want protected. If you don't use this 
	* method you will get a CSRF vulenerability alert and all fields will be filtered.
	* You use this method like so in your form
	* <form method="POST" action="/omgpost">
	* <?php $form = new SecureForm(); $form->protect('list,of,fields,you,do,not,want,filtered'); ?>
	* [rest of form]
	* @param string formName is used with the csrf token.
	* @param string fields list of items you want to not be filtered. This should normally be blank.
	*/
	public function protectForm($formName, $fields = '') {
		$formOutput = '';
		// generate the csrf protection token
		$csrfProtectionToken = hash_hmac('sha256', $this->generateCSRFToken(32), $this->securityKey);
		$this->setCSRFSession($formName, $csrfProtectionToken);
		// generate the field hmac list
		$xssFilterAvoidanceToken = hash_hmac('sha256', $fields, $this->securityKey);
		// outpu the form parameters.
		$formOutput .= "<input type='hidden' name='csrf_token' value='" . $formName . "|" .  $csrfProtectionToken . "' />";
		$formOutput .= "<input type='hidden' name='do_not_filter' value='" . $fields . "' />";
		$formOutput .= "<input type='hidden' name='do_not_filter_token' value='" . $xssFilterAvoidanceToken . "' />";
		echo $formOutput;
	}

	/**
	* safeRequest
	* This will make each request to your application just a touch safer. While I can't promise 
	* that it will fully protect you, it will do an okay job. 
	* It will check for CSRF and clean out POST/GET/REQUEST as well as SERVER variables.
	*/
	public function safeRequest() {
		if($this->validateCSRF()) {
			// we can move forward with the form now and clean it up because we have tested for CSRF.
			// detect if the field names have been tampered with
			if($_SERVER['REQUEST_METHOD'] == 'POST') {
				$fieldsToIgnore = array();
				if(!isset($_POST['do_not_filter']) || $_POST['do_not_filter_token'] !== hash_hmac('sha256', $_POST['do_not_filter'], $this->securityKey)) {
					$this->securityLog("LOG: Do not filter was not existant or tampered with. We are filtering all fields");
				} else {
					$fieldsToIgnore = explode(',', $_POST['do_not_filter']);
				}
				foreach($_POST as $key => $val) {
					if(!in_array($key, $fieldsToIgnore)) {
						$_POST[$key] =  htmlspecialchars($val, ENT_QUOTES, "UTF-8");
						$_REQUEST[$key] = htmlspecialchars($val, ENT_QUOTES, "UTF-8");
					}
				}
				foreach($_GET as $key => $val) {
					if(!in_array($key, $fieldsToIgnore)) {
						$_GET[$key] =  htmlspecialchars($val, ENT_QUOTES, "UTF-8");
						$_REQUEST[$key] = htmlspecialchars($val, ENT_QUOTES, "UTF-8");
					}
				}
			}
		}
	}

	private function filterItems($item) {
		foreach($item as $key => $val) {
			$item[$key] = htmlspecialchars($val, ENT_QUOTES, "UTF-8");
		}
	}
	/**
	* validateCSRF
	* This function performs the validation of the CSRF token against the session
	* This will return either true or perform whatever action needed based on a CSRF
	* @return bool true or false of if the form is okay to continue processing. 
	*/
	public function validateCSRF() {
		if($_SERVER['REQUEST_METHOD'] == 'POST') {
			if(!isset($_POST['csrf_token'])) {
				// we have a form with no CSRF Protection. 
				return $this->CSRFViolation("Post to " . $_SERVER['REQUEST_URI'] . " does not contain CSRF Protection.");
			} else {
				$nameToken = explode("|", $_POST['csrf_token']);
				if($_SESSION[$nameToken[0]] !== $nameToken[1]) {
					return $this->CSRFViolation( $_SERVER['REQUEST_URI'] . " submitted " . $_POST['csrf_token'] . " which does not match the value in the session of: " . $_SESSION[$nameToken[0]] . " (also happens when a form is refreshed)." );
				}
			}
		}
		return true;
	}

	/**
	* CSRFViolation
	* This function will take action on a CSRF attempt and either log, deny or both
	* @param array post array is sent in. 
	*/
	private function CSRFViolation($violation) {
		switch($this->csrfVolationAction) {
			case 'none':
				break;
			case 'log':
				$this->securityLog("LOG: " . $violation);
				break;
			case 'block':
				throw new RuntimeException('CSRF Attack detected');
			case 'log_block':
				$this->securityLog("LOG_BLOCK: " . $violation);
				throw new RuntimeException('CSRF Attack detected and logged');
			default:
				throw new RuntimeException("Who did that?");
		}
		return true;
	}

	/**
	* securityLog
	* This is a simple function to just do a basic log of a security related message
	* @param string message that you want to log
	*/
	private function securityLog($message) {
		$fd = fopen($this->securityLogFile, 'a');
		$str = "[" . date("Y/m/d h:i:s", mktime()) . "] " . $message;
		fwrite($fd, $str . "\n");
		fclose($fd);
	}

	/**
	* setCSRFSession
	* Set the CSRF token in the session of the user so it can be compared later for form validation
	* @param string name of the form we are protecting
	* @param string token that we want to set
	*/
	private function setCSRFSession($name, $token) {
		if(!isset($_SESSION)) {
			session_start();
		}
		$_SESSION[$name] = $token;
	}

	/**
	* generateCSRFToken
	* This function is used to generate the CSRF mitigation token, this token will be
	* sent through a hmac function and will be stored as a cookie in the users browser.
	* @param string length of the token you need to generate.
	* @return token 
	*/
	private function generateCSRFToken($length = 16) {
		$token = '';
		for($i = 0; $i < $length; $i++) {
			$r = mt_rand(0, 61);
			switch(true) {
				case ($r < 10):
					$token .= chr($r+48);
					break;
				case ($r < 36):
					$token .= chr($r+55);
					break;
				default:
					$token .= chr($r+61);
					break; 
			}
		}
		return $token;
	}
}
?>

<?php
session_start();
$sr = new SecureRequests();
$sr->safeRequest();
$val = '';
if(isset($_POST['test_field'])) {
    $val = $_POST['test_field'];
}
?>
<form method="POST" action="secure.requests.php">
<?php $sr->protectForm('test_post', ''); ?>
<input type="text" value="<?php echo $val;?>" name="test_field" />
<input type="submit" value="Go" />
</form>