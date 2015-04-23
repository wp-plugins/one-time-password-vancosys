<?php
/*
Plugin Name: One Time Password Vancosys
Plugin URI: http://vancosys.com
Author: Vancosys Data Solutions
Author URI: http://www.vancosys.com
Description: Authentication for WordPress using the Token as One Time Password generator.
Version: 0.5
Compatibility: WordPress 3.8 and later
License: GPLv2
---------------------------------------------------------------
one line to give the program's name and an idea of what it does.
Copyright (C) 2015  name of author

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
if ( !defined('__DIR__') ) define('__DIR__', dirname(__FILE__)); 







///////////////////////////////////////
/*
=====================
What does this do?
=====================
- get  userid, activate code , seed 
- saving in db where userid client and userid server be one
*/
if(isset($_POST['userid']) && isset($_POST['ac']) && isset($_POST['seed'])  ){
global $wpdb;
$arg_userid=intval($_POST['userid']);
$arg_ac=sanitize_text_field($_POST['ac']);
$arg_seed=sanitize_text_field($_POST['seed']);
/*$arg_userid=sanitize_text_field($arg_userid);
$arg_ac=sanitize_text_field($arg_ac);	
$arg_seed=sanitize_text_field($arg_seed);	
*/
$table_name = $wpdb->prefix . 'otp_vancosys';
$wpdb->update( 
         $table_name, 
        array( 
            'date_req' => time() ,
			'seed' => $arg_seed	,
			'status' => '1'
			
        ), 
		array( 
            'userid' => $arg_userid ,
            'status' => $arg_ac 
			
			
        ), 
        array( 
            '%s' ,
            '%s' ,
			'%s' ,
			) ,
		array( '%d','%s' ) 
    );
	
}
/*
Getting an activation code for activate email if user set secure mode
=====================
What does this do?
=====================
- get  userid, activate code 
- check inputs
- saving in db where userid and active code client and userid and active code server be one
*/
elseif(isset($_POST['userid']) && isset($_POST['ac'])){
 global $wpdb;
$arg_userid=intval($_POST['userid']);
$arg_ac=sanitize_text_field($_POST['ac']);
//$arg_userid=sanitize_text_field($arg_userid);
//$arg_ac=sanitize_text_field($arg_ac);
 $table_name = $wpdb->prefix . 'otp_vancosys';
  // $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name." WHERE userid = %d  ",$arg_userid) );
 //  $results = $wpdb->get_row("SELECT * FROM  ".$table_name."  WHERE userid = $arg_userid ");
   $results =$wpdb->get_results( $wpdb->prepare('SELECT * FROM  '.$table_name.'  WHERE userid = %d ', $arg_userid) );
   if(count( $results)>0 && $results[0]->status==$arg_ac && $results[0]->seed=!""){
	 
   $wpdb->update( 
         $table_name, 
        array( 
            'status' => '1' ,
        ), 
		array( 
            'userid' => $arg_userid ,
            'status' => $arg_ac ,
			
        ), 
        array( 
            '%s' ,
        ) ,
		array( '%d','%s' ) 
    );
	}else{
		$results = $wpdb->get_results( $wpdb->prepare('delete  FROM '.$table_name.' WHERE userid = %d',$arg_userid) );
		
	}
}
/*
=====================
What does this do?
=====================
- get  userid, activate code 
- check input
- send to server
- handle result
*/
elseif( isset($_POST['activate_code'])){
	 $activate_code=sanitize_text_field($_POST['activate_code']);
	$activate_code=hash('sha256',$activate_code,false);
	$data = array('activate_code' => $activate_code);
		foreach($data as $key=>$value) {
			$postvars .= $key . "=" . $value . "&";
		}
	
		$ch = curl_init();
		curl_setopt($ch,CURLOPT_URL, "http://otp.vancosys.com/server/activation.php");
		curl_setopt($ch,CURLOPT_POST, true);
		curl_setopt($ch,CURLOPT_POSTFIELDS,$postvars   );
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // for get result 
		$result = trim(strip_tags(curl_exec($ch))); //remove garbage and get result :D
			//echo $result."889";
		$result=json_decode($result);
		
		switch($result[1]){
		 case "601":
			echo "601";
				
			$table_name = $wpdb->prefix . 'otp_vancosys';
			$wpdb->update( 
					 $table_name, 
					array( 
						'date_req' => time() ,
						'seed' => $result[3],
						'status' => '1'
						
					), 
					array( 
						'status' =>  $activate_code
					), 
					array( 
						'%s' ,
						'%s' ,
						'%s' ,
						) ,
					array( '%s' ) 
				);
		 break;
		 case "602":
				echo "602";
		 break; 
		}
		curl_close($ch);  // close connection handler
	
	
	
}




















//include_once(ABSPATH.'wp-load.php'); 
require_once( dirname( __FILE__ ) . '/check_otp_user.php' );
$GLOBALS['gapup'] = new check_otp_user();

/**
 * Sending the submitted form to check_args.php  and analysis result that.
 * This is called during the authenticate filter, after the user has entered an otp code/otp backup code.
 * 
 * @param  mixed   $user
 * @param  string  $username
 * @param  string  $attempted_password
 * @return mixed
 */
function check_otp( $user, $username = '', $password = '' ) {
global $wpdb;
$userstate = $user;
	$table_name = $wpdb->prefix . 'otp_vancosys';
   $user = get_user_by( 'login', $username ); 
   $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d and status=1',$user->ID) );
if(count($results)>0  ){
		if($_POST['otp']=="" && $_POST['otp_forget_pass']=="" && $_POST['gapup_token_prompt']!="")
			return new WP_Error( 'empty_otp_authenticator_password', __( '<strong>ERROR</strong>:   The OTP Vancosys Authenticator password is empty.', 'OPT-vancosys' ) );
		elseif($_POST['otp']!=""){
		$otp=intval($_POST['otp']);
		$result=otp_check_user_pass($otp,$username);
		/*$data = array('action' => $otp,'auth' => $username);
 foreach($data as $key=>$value) {
    $postvars .= $key . "=" . $value . "&";
  }
		$ch = curl_init();
		curl_setopt($ch,CURLOPT_URL, plugins_url( 'check_args.php', __FILE__ ));
		curl_setopt($ch,CURLOPT_POST, true);
		curl_setopt($ch,CURLOPT_POSTFIELDS, $postvars    );
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$result = curl_exec($ch);
		curl_close($ch);*/
		if(strpos($result, "denied")){
					return new WP_Error( 'invalid_otp_authenticator_password', __( '<strong>ERROR</strong>: The OTP Vancosys Authenticator password is incorrect.', 'OPT-vancosys' ) );

		}else 	return $userstate;
		
		}elseif($_POST['otp_forget_pass']!="" ){
		
						$otp_forget_pass=sanitize_text_field($_POST['otp_forget_pass']);
						$result=otp_forget_pass_checking($otp_forget_pass,$username);
						/*$data = array('otp_forget_pass' => $otp_forget_pass,'auth' => $username);
						foreach($data as $key=>$value) {
						$postvars .= $key . "=" . $value . "&";
						}
						$ch = curl_init();
						curl_setopt($ch,CURLOPT_URL, plugins_url( 'check_args.php', __FILE__ ));
						curl_setopt($ch,CURLOPT_POST, true);
						curl_setopt($ch,CURLOPT_POSTFIELDS, $postvars    );
						curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
						$result = curl_exec($ch);
						curl_close($ch);*/
						if(strpos($result,"denied2")){
						return new WP_Error( 'invalid_otp_authenticator_forget_password', __( '<strong>ERROR</strong>: Your account is temporary locked.', 'OPT-vancosys' ) );
						}elseif(strpos($result,"denied")){
						return new WP_Error( 'invalid_otp_authenticator_forget_password', __( '<strong>ERROR</strong>: The OTP Vancosys Authenticator forget password is incorrect.', 'OPT-vancosys' ) );
						
						}else 	{
							
						setcookie('otp_fid',substr($result,0,40));	
						return $userstate;
						
						}
			}
		}else 	return $userstate;
}

/*=====================
What does this do?
=====================
-  check otp password entered  
-  check inputs
-  check user is a wp user
-  check user is an otp user 
-  add totp for check otp password enterd by user is true or false (if otp diffrent time  sync or ±10 min it's true else false )
*/
function otp_check_user_pass($otp,$username){
	    global $wpdb;
	
$arg_pass=intval($otp);
$arg_auth=sanitize_text_field($username);
if(empty($arg_pass) ){

 wp_logout();
 return "access denied"; 
exit; 
 }
 else{

$table_name = $wpdb->prefix . 'otp_vancosys';
$user = get_user_by( 'login', $arg_auth ); 
//$results = $wpdb->get_row("SELECT * FROM  ".$table_name."  WHERE userid = $user->ID "); 
$results =$wpdb->get_results( $wpdb->prepare('SELECT * FROM  '.$table_name.'  WHERE userid = %d ', $user->ID) );
		if(count($results)>0){
			////////////////////////
			if($results[0]->diff_time=='126'){ //when not set diff_time
			////////////////////////
					$diff_time="";
					require_once  plugin_dir_path( __FILE__ ).'class/totp.class.php';
					require_once  plugin_dir_path( __FILE__ ).'class/big.php';
					$diff_time=-600;
					counter_diff:
					$temp_time = new Math_BigInteger(time()+$diff_time);
					$temp_expire = new Math_BigInteger(60);
					list($quotient, $remainder) = $temp_time->divide($temp_expire);
					// create the object totp
					$clientCode = new TOTP();
					//clean seed from "carriage return" and "line feed"
					$str_seed = str_replace(PHP_EOL, '', $results[0]->seed);
					// set seed 
					$clientCode->setSecretKey(substr($str_seed,0,40));
							
					$clientCode->timeee=$quotient->toString();
					$clientCode->setExpirationTime(60);  //set expire time otp passowrd
					$clientCode->setDigitsNumber(6); //set len otp passowrd			// generate the pass token for checking
					$origCode = $clientCode->generateCode();
					if($origCode==$arg_pass){
							 $wpdb->update( 
								 $table_name, 
								array( 
									'diff_time' =>  $diff_time/60
								), 
								array( 
									'userid' =>$user->ID
									
								), 
								array( 
									'%d' 
								) ,
								array( '%d' ) 
							);
						return $userstate;
					}elseif($diff_time==600){ // if diffrent time token pass >10min logout
						global $wpdb;
						wp_logout();
						return "access denied"; 
						exit; 
					}else{
						$diff_time+=60;
						goto counter_diff;
					}
			}else{ //when set diff_time
			
					$diff_time2=$results[0]->diff_time*60;
					require_once  plugin_dir_path( __FILE__ ).'class/totp.class.php';
					require_once  plugin_dir_path( __FILE__ ).'class/big.php';
					$diff_time=-60;
					counter_diff2:
					$temp_time = new Math_BigInteger(time() + $diff_time2 + $diff_time);
					$temp_expire = new Math_BigInteger(60);
					list($quotient, $remainder) = $temp_time->divide($temp_expire);
					// create the object totp
					$clientCode = new TOTP();
					//clean seed from "carriage return" and "line feed"
					$str_seed = str_replace(PHP_EOL, '', $results[0]->seed);
					// set seed 
					$clientCode->setSecretKey(substr($str_seed,0,40));
							
					$clientCode->timeee=$quotient->toString();
					$clientCode->setExpirationTime(60);  //set expire time otp passowrd
					$clientCode->setDigitsNumber(6); //set len otp passowrd			// generate the pass token for checking
					$origCode = $clientCode->generateCode();
					
					if($origCode==$arg_pass){
							
						return $userstate;
					}elseif($diff_time==60){ // if diffrent time token pass >10min logout
						global $wpdb;
						wp_logout();
						return "access denied"; 
						exit; 
					}else{
						$diff_time+=60;
						goto counter_diff2;
					}				
				
			}		
		}else{
			global $wpdb;
				wp_logout();
				return "access denied"; 
				exit; 
		}
	}
	}
	
	
	
	

/*
=====================
What does this do?
=====================
checking backup code 
*/
function otp_forget_pass_checking($otp_forget_pass,$username){
	global $wpdb;
//elseif(isset($_POST['otp_forget_pass'])){	
$exist_f_pass="NO";
$arg_forget_pass=htmlentities(trim(sanitize_text_field($otp_forget_pass)));
$arg_auth=$username;
$f_pass_user="";

$table_name = $wpdb->prefix . 'otp_vancosys';
$user = get_user_by( 'login', $arg_auth ); 

//$results = $wpdb->get_row("SELECT * FROM  ".$table_name."  WHERE userid = '".$user->ID."'");
$results =$wpdb->get_results( $wpdb->prepare('SELECT * FROM  '.$table_name.'  WHERE userid = %d ', $user->ID) );
		if(count($results)>0 )
			if(checking_limit_login_f_pass($user->ID)){
			$f_pass_user=json_decode($results[0]->f_pass);
			for($i=0;$f_pass_user[$i];$i++){
				if($f_pass_user[$i]==hash('sha256',$arg_forget_pass,false)){

				$exist_f_pass="YES";
					$wpdb->update( 
					 $table_name, 
					array( 
						'limit_f_pass' =>  '0',
						'time_limit_f_pass' =>  '0'
					), 
					array( 
						'userid' => $user->ID 
					), 
					array( 
						'%d',
						'%d'
						
					) ,
					array( '%d' ) 
				);
					//echo sha1(md5($arg_forget_pass));
					return hash('sha256',$arg_forget_pass,false);
					return $userstate;	
				}
				
			}
			if($exist_f_pass=="NO"){
					$wpdb->update( 
					 $table_name, 
					array( 
						'limit_f_pass' => $results[0]->limit_f_pass + '1'
					), 
					array( 
						'userid' => $user->ID 
					), 
					array( 
						'%d',
						
					) ,
					array( '%d' ) 
				);
				return "access denied"; 
					}
		}else{return "access denied2"; }
		
		
		
	
}








/**
 * Remove the backup code entered by the user
 * 
 * @param  integer $userid
 * @param  string  $f_pass
 */
function del_otp_forget_pass($userid,$f_pass){
	global $wpdb;
	$table_name = $wpdb->prefix . 'otp_vancosys';
	//$results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d',$userid) );
	//$results = $wpdb->get_row("SELECT * FROM  ".$table_name."  WHERE userid = $userid and status=1");
	$results =$wpdb->get_results( $wpdb->prepare('SELECT * FROM  '.$table_name.'  WHERE userid = %d and status=1', $userid ) );
	if(count( $results)>0){
		
		$result =str_replace($f_pass,"",$results[0]->f_pass);
		 $wpdb->update( 
         $table_name, 
        array( 
			'f_pass' => $result  
        ), 
		array( 
            'userid' => $userid 
        ), 
        array( 
            '%s' 
        ) ,
		array( '%d' ) 
		);
	}
}
/**
 * Design token prompt and backup code form
 */
function loginform(){
    echo "\t<p id='otpv_login_page'>\n";
    echo "\t\t<label style='font-weight:bold;font-size:16pt;' title=\"".__('OTP Vancosys Authenticator ','otp-authenticator')."\">".__('OTP Vancosys ','wp-otp-vancosys')."<span ></span><br />\n";
   	echo "<img src=".plugin_dir_url( __FILE__ )."otp_login.png style=\"padding: 14%;margin-right: 10%;float: right;\">";
	echo "\t\t<input type=\"password\"  name=\"otp\" id=\"otp\" class=\"input\" value=\"\" size=\"20\" style=\"text-align: center;ime-mode: inactive;\" /></label>\n";
    echo "\t</p>\n";
	////////////////////////////////////////////////////
	 echo "\t<p id='otpv_forget_page' style='display:none'>\n";
    echo "\t\t<label style='font-weight:bold;font-size:16pt;' title=\"".__('OTP Vancosys Authenticator ','otp-authenticator')."\">".__('Enter your forget OTP password ','wp-otp-vancosys')."<span ></span><br />\n";
   	echo "<img id='otpv_img' src=".plugin_dir_url( __FILE__ )."otp_login.png style=\"padding: 14%;margin-right: 10%;float: right;\">";
	echo "\t\t<input type=\"password\"  name=\"otp_forget_pass\" id=\"otp\" class=\"input\" value=\"\" size=\"20\" style=\"text-align: center;ime-mode: inactive;\" /></label>\n";
    echo "\t</p>\n";
	///////////////////////////////////////////////////
	echo "<style>
	#gapup_token_prompt{
			width: 100%;
padding: 0px;
margin: 0px;
float: left;
		}
		form{
		text-align:center;
		}
	
	
			</style>
			<script>
function otpv_forget(){
	
	document.getElementById('otp').value='';
	document.getElementById('otpv_forget_page').style.display='block';
	document.getElementById('otpv_login_page').style.display='none';
	document.getElementById('otpv_link_forget').style.display='none';
	document.getElementById('otpv_img').src='".plugin_dir_url( __FILE__ )."forgot-password.png';

	
	
}
</script>
			";
?>

<?php
}
/**
 * User management page and check if user's webmaster or standard user
 * 
 */
function add_user_opt(){
    global $wpdb;
    global $current_user;
 $table_name = $wpdb->prefix . 'otp_vancosys';
 
echo '
<p id="user_set" style="font-weight: bold;font-size: 13pt;">Vancosys OTP Registeration</p>';


echo '        
            ';
echo '
<div class="wrap" id="otpv-page2" style="display:none">
<p style="display:none" id="users_title">Username:</p>
<p>
<input  value="" type="txt" name="username" id="users" Disabled style="display:none">
</p>

<p>
OTP Serial Code:
 
 </p>
 <p>
<input  required value="" type="txt" name="serial" id="serial">
</p>
 <p>
 
OTP Secret Code:
 
</p>

<p>
<input required value="" type="txt" name="secret" id="secret">
</p>





<br>
<hr>
<p>
 <h3>
Registeration Type :
 </h3>
</p>

<p>
<input type="radio" name="type" class="type" value="1" checked onclick="document.getElementById(\'mobile\').style.display=\'none\';document.getElementById(\'email\').style.display=\'none\'">Simple:<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This is the simplest way to register your Vacnosys OTP with your user in Wordpress, In this mode you or anyone else who have the Secret Code and your OTP serial number also can register this OTP in another CMS or application without your notice, If you destroy your secret code after use nobody can abuse this OTP never but you also can’t use this OTP in other systems.
</p>

<p>
<input type="radio" name="type" class="type" value="2" onclick="document.getElementById(\'mobile\').style.display=\'none\';document.getElementById(\'email\').style.display=\'block\';" >Secure with Email: <br>
When you are using this option for registering your OTP you will be known as official owner of token by your email address, it means each time you want to register this token in another systems you will notify by an email and registration only possible when we have your approval by clicking the yes link in email we sent to you. <br>
For the OTP registered before by this option; email will be send to email address you registered first time.

	
<p>
<input  value="" type="txt" name="email" id="email" style="display:none" placeholder="Enter your email address">
</p>

</p>

<p>
<input disabled type="radio" name="type" class="type" value="3" onclick="alert(\'This item is not available in current version!\')">Secure With phone number:<br>
When you are using this option for registering your OTP you will be known as official owner of token by your phone number, it means each time you want to register this token in another systems you will notify by an TEXT/SMS sending to your phone and registration only possible when you have the secret registration code we sent to your phone number.<br>
For the OTP registered before by this option; TEXT/SMS will be send to phone number you registered first time
 

	<p>
		<input  value="" type="txt" name="mobile" id="mobile" style="display:none" placeholder="Enter your mobile number">
	</p>

</p>
<p>
<hr>
<h3>
Backup codes:
</h3>


</p>
<p>
Backup code will help you in the case that you don’t have access to your OTP or maybe you lost it and want to login in your Wordpress, You can print or download backup codes and keep it safe. 
<br>
Number of required Backup code: <select required name="otpv_count_forget_pass" id="otpv_count_forget_pass">
	<option selected="selected" value="1">1</option>
	<option value="2">2</option>
	<option value="3">3</option>
	<option value="4">4</option>
	<option value="5">5</option>
	</select>
</p>
<p id="view_backup_code">
<input type="button" onclick="create_backup();" value="Create Backup Code"  id="creat_backup" style="background: brown;color: #fff;">
<p id="view_backup_code_display" style="color:red;display:none;"><label><b>Your Backup Code:<br></b></label><label id="view_backup_code_fields"></label>
<div class="border-color: #dd3d36;border-left: 4px solid #dd3d36;">
<b>Attention</b>: Backup codes are display only once , It’s better to print or note them if possible 
</div>
</p>
</p>
<p>
<input type="button" onclick="send();" value="Send for check" name="sbmt" id="sbmt"><input type="button" style="display:none" class="button-primary " value="Activate User" name="sbmt" id="user" onclick="setuser();">
</p>

<p>
<input type="button" onclick="del();" value="Deactive"  id="del">
</p>
<p>
</p>
</div>
<div class="clear"></div>

<script>
function create_backup(){
	var otpv_count_forget_pass= document.getElementById("otpv_count_forget_pass").value;
	var otpv_username= document.getElementById("users").value;
		jQuery.post( ajaxurl, {action: "req_back", req_back:1,count:otpv_count_forget_pass,username:otpv_username },function(response) {	
	
				document.getElementById("view_backup_code_display").style.display="block";
				document.getElementById("view_backup_code_fields").innerHTML=response;
			
	});
	
}
function user(username){
document.getElementById("user").style.display="inherit";
document.getElementById("sbmt").style.display="none";
document.getElementById("otpv-page2").style.display="";
document.getElementById("otpv-page1").style.display="none";
document.getElementById("otpv_big").style.display="none";
document.getElementById("users").style.display="inherit";
document.getElementById("users_title").style.display="inherit";
document.getElementById("users").value=username;
//alert("Please fill required fields then click on button \"active user\"");
}
function activate(){
	var activate_code =document.getElementById("activate_code").value;
	jQuery.post( ajaxurl, {action: "otp_activate", activate_code:activate_code },function(response) {
	if(response=="601"){
					 document.getElementById("otpv-page3-value").innerHTML="Congratulation, your token successfully registered ";
					activate_code="ok";
				}else if(response=="602"){
					alert(\'Your activation code is wrong please try again\');
					activate_code="ok";
				}
	});
	
}
function setuser(){
var activate_code="";
var secret =document.getElementById("secret").value;
var serial= document.getElementById("serial").value;
var mobile= document.getElementById("mobile").value;
var email= document.getElementById("email").value;
var username= document.getElementById("users").value;
var otpv_count_forget_pass= document.getElementById("otpv_count_forget_pass").value;
var type= jQuery(\'input[name="type"]:checked\').val();
if( secret && serial && type==3 && mobile!=""){
jQuery.post( ajaxurl, {action: "otp_setuser",  username:username,secret:secret, serial:serial,mobile:mobile,type:type,otpv_count_forget_pass:otpv_count_forget_pass },function(response) {

  document.getElementById("otpv-page3").style.display="block";
  document.getElementById("otpv-page2").style.display="none";
  document.getElementById("otpv-page3-value").innerHTML=response;
 // document.getElementById("otpv-page3-value").innerHTML+=" <input type=\"txt\" id=\"activate_code\" name=\"activate_code\" value=\"\"><input type=\"button\" name=\"send\" value=\"Send checking\" onclick=\"activate();\">  ";


	
	
	});
  }else if(secret && serial && type==1 ){
  jQuery.post(  ajaxurl, {action: "otp_setuser", username:username,secret:secret, serial:serial,type:type,otpv_count_forget_pass:otpv_count_forget_pass },function(response) {
  document.getElementById("otpv-page3").style.display="block";
  document.getElementById("otpv-page2").style.display="none";
  document.getElementById("otpv-page3-value").innerHTML=response;

  //location.reload(true); 
	});
  }else if(secret && serial && type==2 && email!=""){
	jQuery.post( ajaxurl, {action: "otp_setuser", username:username,secret:secret, serial:serial,type:type,otpv_count_forget_pass:otpv_count_forget_pass,email:email },function(response) {
  document.getElementById("otpv-page3").style.display="block";
  document.getElementById("otpv-page2").style.display="none";
  document.getElementById("otpv-page3-value").innerHTML=response;
	});  
  }else{ 
	  if(secret=="" || serial=="")
	  alert("Please fill Secret code and Serial device");
	  else if(email=="" && type==2 )
	  alert("Please fill Email address");
	  else if(mobile=="" && type==3 )
	  alert("Please fill mobile number");
  }

}
function send(){
var activate_code="";
var secret =document.getElementById("secret").value;
var serial= document.getElementById("serial").value;
var mobile= document.getElementById("mobile").value;
var email= document.getElementById("email").value;
var otpv_count_forget_pass= document.getElementById("otpv_count_forget_pass").value;
var type= jQuery(\'input[name="type"]:checked\').val();
if( secret && serial && type==3 && mobile!=""){
jQuery.post(ajaxurl ,{action:"send", secret:secret, serial:serial,mobile:mobile,type:type,otpv_count_forget_pass:otpv_count_forget_pass },function(response) {

  document.getElementById("otpv-page3").style.display="block";
  document.getElementById("otpv-page2").style.display="none";
  document.getElementById("otpv-page3-value").innerHTML=response;
	while(activate_code != "ok" ) {
  	activate_code = prompt("Please enter activate code", "");

		jQuery.post( "'.plugin_dir_url( __FILE__ ).'check_args.php", {activate_code:activate_code },function(response2) {
			alert(response2);
			alert(activate_code);
				if(response2==\'601\'){
					 document.getElementById("otpv-page3-value").innerHTML="your code is valid";
					activate_code="ok";
				}else if(response2==\'602\'){
					alert(\'your code is incorrect\');
					activate_code="";
					
				}
			 
		});
	}
	});
  }else if(secret && serial && type==1  ){
  jQuery.post( ajaxurl ,{action:"send", secret:secret, serial:serial,type:type,otpv_count_forget_pass:otpv_count_forget_pass },function(response) {

  document.getElementById("otpv-page3").style.display="block";
  document.getElementById("otpv-page2").style.display="none";
  document.getElementById("otpv-page3-value").innerHTML=response;
	});
  }else if(secret && serial && type==2 && email!="" ){
	  jQuery.post( ajaxurl ,{action:"send",secret:secret, serial:serial,email:email,type:type,otpv_count_forget_pass:otpv_count_forget_pass },function(response) {

  document.getElementById("otpv-page3").style.display="block";
  document.getElementById("otpv-page2").style.display="none";
  document.getElementById("otpv-page3-value").innerHTML=response;
	});  
  }else{
	   if(secret=="" || serial=="")
	  alert("Please fill Secret code and Serial device");
	  else if(email=="" && type==2 )
	  alert("Please fill Email address");
	  else if(mobile=="" && type==3 )
	  alert("Please fill mobile number");
	  }
  }
  function del(){
var username= document.getElementById("users").value;
if(username)
	jQuery.post( ajaxurl,{action:"otp_del" ,deactive:1,username:username},function(response) {
  alert(  response );
	location.reload(true); 
	});
else
jQuery.post(  ajaxurl,{action:"otp_del_current_user" },function(response) {
  alert(  response );
location.reload(true); 
	 jQuery( "#del" ).prop( "disabled", true );
	});
  }
  


</script>
';
if (current_user_can( 'manage_options' )) {
?>
<big id="otpv_big" style="text-align: center;margin-right: auto;margin-left: auto;display:block;background: gainsboro;padding: 13px;width: 50%;">From the first, Select a user as one OTP user </big>
<!-- Table goes in the document BODY -->
<link rel='stylesheet' href='<?php echo plugin_dir_url( __FILE__ )?>table-style.css' type='text/css' media='all' />

<table class="gradienttable" style="width: 90%;
text-align: center;
font-weight: bold;
margin-top: 12px;
margin-left: auto;
margin-right: auto;" id="otpv-page1">
<caption style="font-weight: bold;
background: silver;
border-radius: 10px 10px 0px 0px;">
List Users
</caption>
	<tr>
	<th><p>UserID</p></th><th><p>UserName</p></th><th><p>Email</p></th><th><p>Status</p></th>
</tr>
<?php $blogusers = get_users( 'blog_id=1&orderby=nicename' );
// Array of WP_User objects.
foreach ( $blogusers as $user ) {
	echo '
<tr  onclick="user(\''.$user->user_nicename.'\')" style="cursor:pointer">
	<td><p>'.esc_html( $user->ID ).'</p></td><td><p>'.esc_html( $user->user_nicename ).'</p></td><td><p>'.esc_html( $user->user_email ).'</p></td><td><p><a style="cursor:pointer" href="javascript:void(0);"  onclick="user(\''.$user->user_nicename.'\')" >'.check_user_is_otp($user->ID ).'</a></p></td>
</tr>';
}?>



</table>
<div class="notice" id="otpv-page3" style="display:none;text-align:center;direction: ltr;">
<p id="otpv-page3-value"></p>
<br>
<a class="button-back-otp" onclick="location.reload(true);">Go back</a>
</div>
<?php
}else{
?>
<script>document.getElementById("otpv-page2").style.display="block"; </script>
<div class="notice" id="otpv-page3" style="display:none;text-align:center;direction: ltr;">
<p id="otpv-page3-value"></p>
<br>
<a class="button-back-otp" onclick="location.reload(true);">Go back</a>
</div>
<?php
}
  $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d',$current_user->ID) );
  if(count($results)>0){
  echo '	<script>  jQuery( "#del" ).prop( "disabled", false );
			document.getElementById("sbmt").value="You are an OTP user";
			jQuery( "#sbmt" ).prop( "disabled", true )
  </script>';
  
  }
  else
  echo 	' <script> //jQuery( "#del" ).prop( "disabled", true );
				jQuery( "#sbmt" ).prop( "disabled", false )
  </script>';

}


function loginfooter(){

echo '<noscript><meta http-equiv="refresh" content="0;url='.plugin_dir_url( __FILE__ ).'nojs.php"></noscript>   '; 

echo '<noscript>You dont have javascript enabled! Please Enable Javascript!</noscript>';


}
/*
* Install table on database
*/
function insert_table(){

global $wpdb;

    $table_name = $wpdb->prefix . 'otp_vancosys';

    $sql = "CREATE TABLE $table_name (
      id int(11) NOT NULL AUTO_INCREMENT,
      date_req int(11) DEFAULT NULL,
      userid bigint(20) DEFAULT NULL,
      seed varchar(200) DEFAULT NULL,
      f_pass text DEFAULT NULL,
      status  varchar(200) DEFAULT NULL,
      limit_f_pass  tinyint(4) DEFAULT '0'  NOT NULL,
      time_limit_f_pass  int(11) DEFAULT '0' NOT NULL,
      diff_time  tinyint(4) DEFAULT '126' NULL,
      UNIQUE KEY id (id)
    );";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );


}
/*
* Remove table from database
*/
function delete_table(){

	global $wpdb;
	$table_name = $wpdb->prefix . 'otp_vancosys';

    $sql = "TRUNCATE TABLE `$table_name`   ";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );


}
/*
* Show status users on admin page 
* @param  integer $userid
* @return string
*/
function check_user_is_otp($userid){
    global $wpdb;
 $table_name = $wpdb->prefix . 'otp_vancosys';
 //$results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d',$userid) );
 //$results = $wpdb->get_row("SELECT * FROM  ".$table_name."  WHERE userid = $userid ");
 $results =$wpdb->get_results( $wpdb->prepare('SELECT * FROM  '.$table_name.'  WHERE userid = %d ', $userid ) );
if(count( $results)>0)
	if($results[0]->seed!="")
     return "UnSet from OTP user";
	else
     return "Waiting for reply";		
else
return "Set to OTP user";
}
/*
* Remove the backup code entered by the user
*/

function del_f_pass() {
    global $wpdb;	
  del_otp_forget_pass( get_current_user_id(),$_COOKIE['otp_fid']);
}
function vancosys_menu_page(){
    add_menu_page( 'OTP Vancosys settings', 'OTP Vancosys', 'read', 'OTP_Vancosys', 'add_user_opt', plugins_url( 'wp-otp-vancosys/Header.png' ), 6 ); 
	}

function register_session(){
    if( !session_id() )
        session_start();
}

/*
 * Register callback methods for WordPress hooks
 */
add_action( 'loop_start', 'del_f_pass' );
add_filter( 'authenticate', 'check_otp' , 50, 3 );
register_activation_hook( __FILE__, 'insert_table' );
add_action( 'admin_menu', 'vancosys_menu_page' );

add_action('init','register_session');




function ajax_OTP_Vancosys_req_back(){
	
	$count_backup=intval($_POST['count']);
	if(current_user_can( 'manage_options' )){
		$username=sanitize_text_field($_POST['username']);
		$user = get_user_by( 'login', $username );  //get user information  
			if($user->id)
				echo str_replace("|"," <br> ",create_backup($count_backup,$user->id));
		}else{
			$user = wp_get_current_user();
			if($user->id)
				echo str_replace("|"," <br> ",create_backup($count_backup,$user->id));
	
		}

	  die();
}
function create_backup($f_pass_count=4 ,$userid ){
	
global $wpdb;
$otpv_f_pass='';
$otpv_f_pass_e='';
$table_name = $wpdb->prefix . 'otp_vancosys';
for($i=0;$i<$f_pass_count;$i++){
$otpv_f_pass_temp=  sprintf("%08d", mt_rand(1, 99999999));
$otpv_f_pass.=  $otpv_f_pass_temp.'|';
$otpv_f_pass_e.=  hash('sha256',$otpv_f_pass_temp,false).'|';
}
   $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d',$userid) );
if(count( $results)<1)
    $wpdb->insert( 
         $table_name, 
        array( 
            'date_req' => time() ,
            'userid' => $userid,
			'f_pass'=>json_encode(explode("|",$otpv_f_pass_e)),
        ), 
        array( 
            '%s' ,
            '%d' ,
			'%s' 
        ) 
    );
else{
   $wpdb->update( 
         $table_name, 
        array( 
			'f_pass' => json_encode(explode("|",$otpv_f_pass_e)) ,
        ), 
		array( 
            'userid' => $userid 
        ), 
        array( 
            '%s' 
        ) ,
		array( '%d' ) 
    );
	}
		return $otpv_f_pass;
}
function ajax_OTP_Vancosys_setuser(){
	
	
if (current_user_can( 'manage_options' ) ) {
$arg_serial=sanitize_text_field($_POST['serial']);
$arg_secret=sanitize_text_field($_POST['secret']);
$arg_mobile=sanitize_text_field($_POST['mobile']);
$arg_email=sanitize_email($_POST['email']);
$arg_count_forget_pass=sanitize_text_field($_POST['otpv_count_forget_pass']);
$arg_type=intval($_POST['type']);
$arg_username=sanitize_user($_POST['username']);
$user = get_user_by( 'login', $arg_username );  //get user information  
		if(checking_user_exist($user->ID)){
			
		/////////////////////////////////////
		$data = array('data' => $arg_serial,'secret' =>$arg_secret ,'mobile'=>$arg_mobile,'userid' =>$user->ID,'website' =>  plugin_dir_url( __FILE__ ),'email' =>  $arg_email,'type' =>  $arg_type,'name' =>  $user->user_nicename,'count_forget_pass'=>$arg_count_forget_pass,'type_site'=>'wp');
		foreach($data as $key=>$value) {
			$postvars .= $key . "=" . $value . "&";
		}
		$ch = curl_init();
		curl_setopt($ch,CURLOPT_URL, "http://otp.vancosys.com/server/test.php");
		curl_setopt($ch,CURLOPT_POST, true);
		curl_setopt($ch,CURLOPT_POSTFIELDS,$postvars   );
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // for get result 
		$result = trim(strip_tags(curl_exec($ch))); //remove garbage and get result :D
		$result=json_decode($result);
		switch($result[1]){
		 case "500":
			echo "Sry,Your serial number or  Secret Key not exist or already in use";
		 break;
		 case "301":
				$active_code=$result[3];
				add_otp_user2($user->ID,$active_code);
				echo "This serial number is already registered!\n
				Please wait to be approved<br>";
		 break; 
		  case "400":
				echo "You are registered";
		 break; 
		 // get seed and save in db as well as userid,forgot passwords 
		 case '200':
				echo "Your request has been submitted successfully";
				$otpv_f_pass=add_otp_user($result[3],$user->ID); //save seed, userid; make forgot passowrds and return it
		 break; 
		 case '300':
				add_otp_user2($user->ID,$result[3]);
				echo "Your information is temporarily recorded but for final registration you must check your email and click on activation link.   <br>";
		 break;
		  case '600':
			add_otp_user2($user->ID,$result[3]);
			echo "Your information is temporarily recorded <br>
					For final registration, enter the registration code that will be sent to you via SMS in the box below.<br>";
			echo "
			<input type=\'txt\' id=\"activate_code\" name=\"activate_code\" value=\"\"><input type=\"button\" name=\"send\" value=\"Send checking\" onclick=\"activate();\">
			";
		 break;
		  case '603':
				$active_code=$result[3];
				add_otp_user2($user->ID,$active_code);
		   echo  "This serial number is already registered!<br>
				Please wait to be approved<br>";
			
			echo "
			<input type=\'txt\' id=\"activate_code\" name=\"activate_code\" value=\"\"><input type=\"button\" name=\"send\" value=\"Send checking\" onclick=\"activate();\">
			";
		
		  
		 break;
		 // case 'you cant':
			//	echo "This serial is shared and you can not assign your.";
		// break;
		}
		curl_close($ch);  // close connection handler
		  }// end checking exist user
		  else echo "Dear user you have already registered your token with your specification If you wish, you can press the Deactive button and repeat the registration process";
			  
///////////////////////////////////////////////
}//end if check manage option 
	
	die();
	
}

	
function ajax_OTP_Vancosys_send(){

$arg_serial=sanitize_text_field($_POST['serial']);
$arg_secret=sanitize_text_field($_POST['secret']);
$arg_mobile=sanitize_text_field($_POST['mobile']);
$arg_email=sanitize_email($_POST['email']);
$arg_count_forget_pass=intval($_POST['otpv_count_forget_pass']);
$arg_type=intval($_POST['type']);
$current_user = wp_get_current_user();
if(checking_user_exist($current_user->ID)){
/////////////////////////////////////
$data = array('data' => $arg_serial,'secret' =>$arg_secret ,'mobile'=>$arg_mobile,'userid' => $current_user->ID,'website' => plugin_dir_url( __FILE__ ),'email' =>  $arg_email,'type' =>  $arg_type,'name' =>  $current_user->user_nicename,'count_forget_pass'=>$arg_count_forget_pass,'type_site'=>'wp');

 foreach($data as $key=>$value) {
    $postvars .= $key . "=" . $value . "&";
  }
$ch = curl_init();
curl_setopt($ch,CURLOPT_URL, "http://otp.vancosys.com/server/test.php");
curl_setopt($ch,CURLOPT_POST, true);
curl_setopt($ch,CURLOPT_POSTFIELDS,$postvars   );
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$result = ltrim(strip_tags(curl_exec($ch)));
curl_close($ch);

$result=json_decode($result);

//////////////////////////////////////
		switch($result[1]){
		 case '500':
			echo "Sry,Your Serial Number or Secret Key not exist";
		 break;
		 case '301':
				$active_code=$result[3];
				add_otp_user2( $current_user->ID,$active_code);
				echo "This serial number is already registered!\n
				Please wait to be approved.<br>";
		 break; 
		 case '200':
				echo "Your request has been submitted successfully";
				$otpv_f_pass=add_otp_user($result[3],$current_user->ID,$arg_count_forget_pass);
				
				
		 break;
		 case '300':
				add_otp_user2($current_user->ID,$result[3],$result[5]);
				echo "Your information is temporarily recorded but for final registration you must check your email and click on activation link.<br>";
				
		 break;
		case '600':
			add_otp_user2($user->ID,$result[3],$result[5]);
			echo "Your information is temporarily recorded <br>
			For final registration, enter the registration code that will be sent to you via SMS in the box below.";
		 break;
		   case '603':
				$active_code=$result[3];
				add_otp_user2($user->ID,$active_code,$result[5]);
		   echo  "This serial number is already registered!<br>
				Please wait to be approved<br>	";
			echo "
			<input type=\'txt\' id=\"activate_code\" name=\"activate_code\" value=\"\"><input type=\"button\" name=\"send\" value=\"Send checking\" onclick=\"activate();\">
			";
		  
		 break;
		// case 'you cant':
			//	echo "This serial is shared and  and you can not assign your.";
		// break;
		 }
	}  else echo "Dear user you have already registered your token with your specification If you wish, you can press the Deactive button and repeat the registration process";
	die();
}


function add_otp_user($seed,$userid){    
	global $wpdb;
 $table_name = $wpdb->prefix . 'otp_vancosys';
   $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d',$userid) );
if(count( $results)<1)
    $wpdb->insert( 
         $table_name, 
        array( 
            'date_req' => time() ,
            'userid' => $userid,
			'seed' => $seed	,
			'status'=>'1'
        ), 
        array( 
            '%s' ,
            '%d' ,
			'%s' ,
			'%d'
        ) 
    );
else{
   $wpdb->update( 
         $table_name, 
        array( 
            'date_req' => time() ,
			'seed' => $seed	,
			'status' => '1'
        ), 
		array( 
            'userid' => $userid 
        ), 
        array( 
            '%s' ,
            '%s' ,
			'%d'
        ) ,
		array( '%d' ) 
    );
	}
	//return $otpv_f_pass;
}
function add_otp_user2($userid,$activation){
    global $wpdb;
 $table_name = $wpdb->prefix . 'otp_vancosys';
   $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d',$userid) );
if(count( $results)<1)
    $wpdb->insert( 
         $table_name, 
        array( 
            'date_req' => time() ,
            'userid' => $userid,
			'status'=>$activation

        ), 
        array( 
            '%s' ,
            '%d' ,
			'%s'
        ) 
    );
else{
   $wpdb->update( 
         $table_name, 
        array( 
            'date_req' => time() ,
			'status' => $activation
			
        ), 
		array( 
            'userid' => $userid 
        ), 
        array( 
            '%s' ,
			'%s'
        ) ,
		array( '%d' ) 
    );
	}
}
function checking_user_exist($userid){
global $wpdb;
 $table_name = $wpdb->prefix . 'otp_vancosys';
   $results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d status>0',$userid) );
	if(count( $results)>0)
		return false;
	else
		return true;
	
	
}
function checking_limit_login_f_pass($userid){
global $wpdb;
 $table_name = $wpdb->prefix . 'otp_vancosys';
$results = $wpdb->get_results( $wpdb->prepare('SELECT * FROM '.$table_name.' WHERE userid = %d and limit_f_pass < %d and time_limit_f_pass < %d' ,$userid,3,time()) );	

if(count( $results)>0)
return true;
else
{
	  $wpdb->update( 
	 $table_name, 
	array( 
		'time_limit_f_pass' => time()+'180' ,
		
	), 
	array( 
		'userid' => $userid 
	), 
	array( 
		'%d' ,
	) ,
	array( '%d' ) 
);
return false;
}
	
}
/*
=====================
What does this do?
=====================
deactivate user
*/
function ajax_OTP_Vancosys_del(){
	
	global $wpdb;
 global $current_user;
 $table_name = $wpdb->prefix . 'otp_vancosys';
$username=sanitize_text_field($_POST['username']);
$user = get_user_by( 'login', $username ); 
$results = $wpdb->get_results( $wpdb->prepare('delete  FROM '.$table_name.' WHERE userid = %d',$user->ID) );
echo "Deactivated";		
	
	die();
}
/*
=====================
What does this do?
=====================
deactivate current user if send invalid request or request deactive
*/

function ajax_OTP_Vancosys_del_current_user(){

global $wpdb;
global $current_user;
$table_name = $wpdb->prefix . 'otp_vancosys';
 $results = $wpdb->get_results( $wpdb->prepare('delete  FROM '.$table_name.' WHERE userid = %d',$current_user->ID) );
echo "You Deactivate";
die();
}
add_action('wp_ajax_req_back', 'ajax_OTP_Vancosys_req_back');
add_action('wp_ajax_otp_setuser', 'ajax_OTP_Vancosys_setuser');
add_action('wp_ajax_otp_send', 'ajax_OTP_Vancosys_send');
add_action('wp_ajax_otp_del', 'ajax_OTP_Vancosys_del');
add_action('wp_ajax_otp_del_current_user', 'ajax_OTP_Vancosys_del_current_user');

?>