<?php

define('ENABLE_GUARDIANKEY', true);
define('AES_256_CBC', 'aes-256-cbc');

class guardiankey {

    private $GKconfig = array(
                                'orgid' => "",
                                'authgroupid' => "",
                                'key' => "",
                                'iv' => "",
                                'service' => "SEI",      /* Your service name*/
                                'agentid' => "SeiServer",  /* ID for the agent (your system) */
                                'reverse' => "True" /* If you will locally perform a reverse DNS resolution  */
                                );

    private $api_url        = 'https://gk.DOMINIO.gov.br'; 
    private $collector_host = "gk.DOMINIO.gov.br";
    
    function check_extensions()
    {
        $nook=False;
        $extensions=array("curl");
        
        foreach($extensions as $ext){
            if ( !extension_loaded ($ext) )
            {
                echo "You have to install the PHP extension $ext\n";
                $nook=1;
            }
        }
        if($nook)
            exit;
    }

    function __construct($GKconfig=null)
    {
        $this->check_extensions();
        if($GKconfig!=null)
            $this->GKconfig = $GKconfig;
    }

    function _json_encode($obj)
    {
        array_walk_recursive($obj, function (&$item, $key) {
            $item = utf8_encode($item);
        });
        return json_encode($obj);
    }


    function getUserIP()
    {
        if( array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER) && !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ) {
            if (strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ',')>0) {
                $addr = explode(",",$_SERVER['HTTP_X_FORWARDED_FOR']);
                return trim($addr[0]);
            } else {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            }
        } else {
            return $_SERVER['REMOTE_ADDR'];
        }
    }


    function create_message($username, $useremail="", $attempt = 0, $eventType="Authentication")
    {
        $GKconfig = $this->GKconfig;
        $keyb64 = $GKconfig['key'];
        $ivb64 = $GKconfig['iv'];
        $agentid = $GKconfig['agentid'];
        $orgid = $GKconfig['orgid'];
        $authgroupid = $GKconfig['authgroupid'];
        $reverse = $GKconfig['reverse'];
        $timestamp = time();
        if (strlen($agentid) > 0) {
            $key = base64_decode($keyb64);
            $iv = base64_decode($ivb64);

            $json = new stdClass();
            $json->generatedTime = $timestamp;
            $json->agentId = $agentid;
            $json->organizationId = $orgid;
            $json->authGroupId = $authgroupid;
            $json->service = $GKconfig['service'];
            $json->clientIP = $this->getUserIP();
            $json->clientReverse = ($reverse == "True") ? gethostbyaddr($json->clientIP) : "";
            $json->userName = $username;
            $json->authMethod = "";
            $json->loginFailed = $attempt;
            $json->userAgent = substr($_SERVER['HTTP_USER_AGENT'], 0, 500);
            $json->psychometricTyped = "";
            $json->psychometricImage = "";
            $json->event_type=$eventType; // "Authentication" "Bad access"  ou "Registration"
            $json->userEmail=$useremail;
            $tmpmessage = $this->_json_encode($json);
            $blocksize = 8;
            $padsize = $blocksize - (strlen($tmpmessage) % $blocksize);
            $message = str_pad($tmpmessage, $padsize, " ");
            $cipher = openssl_encrypt($message, 'aes-256-cfb8', $key, 0, $iv);
            return $cipher;
        }
    }

    function sendevent_udp($username, $useremail="", $attempt = "0", $eventType = 'Authentication')
    {
        $GKconfig = $this->GKconfig;
        $cipher = $this->create_message($username, $useremail, $attempt, $eventType);
        $payload = $GKconfig['authgroupid'] . "|" . $cipher;
        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_sendto($socket, $payload, strlen($payload), 0, $collector_host, "8888");
    }
   
   function sendevent($username, $useremail="", $attempt = "0", $eventType = 'Authentication')
    {
       $GKconfig = $this->GKconfig;
        $guardianKeyWS = $this->api_url+"/sendevent";
        $message = $this->create_message($username, $useremail, $attempt, $eventType);
        $tmpdata = new stdClass();
        $tmpdata->id = $GKconfig['authgroupid'];
        $tmpdata->message = $message;
        $data = $this->_json_encode($tmpdata);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($ch, CURLOPT_URL, $guardianKeyWS);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data)
        ));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $return = curl_exec($ch);
        curl_close($ch);
    }



    function checkaccess($username, $useremail="", $attempt = "0", $eventType = 'Authentication')
    {
        $GKconfig = $this->GKconfig;
        $guardianKeyWS = $this->api_url+'/checkaccess';
        $message = $this->create_message($username, $useremail, $attempt, $eventType);
        $tmpdata = new stdClass();
        $tmpdata->id = $GKconfig['authgroupid'];
        $tmpdata->message = $message;
        $data = $this->_json_encode($tmpdata);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_URL, $guardianKeyWS);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data)
        ));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
//         curl_setopt($ch, CURLOPT_VERBOSE, true);
        $return = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);
        
        
        try {
            $foo = json_decode($return);
            return $return;
        } catch (Exception $e) {
            return '{"response":"ERROR"}';
        }
    }
    
    /*
     * Optionally, you can set the notification parameters, such as:
     *   - notify_method: email or webhook
     *   - notify_data: A base64-encoded json containing URL (if method is webhook), server and SMTP port, user, and email password.
     * Example for e-mail:
     * $notify_method = 'email';
     * $notify_data = base64_encode('{"smtp_method":"TLS","smtp_host":"smtp.example.foo","smtp_port":"587","smtp_user":"myuser","smtp_pass":"mypass"}');
     * Example for webhook:
     * $notify_method = 'webhook';
     * $notify_data = base64_encode('{"webhook_url":"https://myorganization.com/guardiankey.php"}');
     */
    function register($email, $notify_method = null, $notify_data_json = null)
    {
        $guardianKeyWS = $this->api_url+'/register';
        // Create new Key
        $key = openssl_random_pseudo_bytes(32);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(AES_256_CBC));
        $agentid = sha1(base64_encode(openssl_random_pseudo_bytes(20)));
        $keyb64 = base64_encode($key);
        $ivb64 = base64_encode($iv);

        $data = array(
            'email' => $email,
            'keyb64' => $keyb64,
            'ivb64' => $ivb64
        );
        
        if($notify_method!=null && $notify_data_json!=null)
        {
            $data = array(
                'email' => $email,
                'keyb64' => $keyb64,
                'ivb64' => $ivb64,
                'notify_method' => $notify_method,
                'notify_data' => $notify_data_json
            );
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $guardianKeyWS);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
//         curl_setopt($ch, CURLOPT_VERBOSE, true);
        $returned = curl_exec($ch);
        curl_close($ch);
        $returns = @json_decode($returned);
        if ($returns === null) {
            throw new Exception('An error ocurred: ' . $returned);
        } else {
            return array(   "email"=> $email,
                            "agentid"=> $agentid,
                            "key"=>$keyb64,
                            "iv"=>$ivb64,
                            "orgid"=>$returns->organizationId,
                            "groupid"=>$returns->authGroupId
                        );
        }
    }
    
    function processWebHookPost($authgroupid=null,$keyb64=null,$ivb64=null)
    {
        
        if($authgroupid==null){
            $GKconfig = $this->GKconfig;
            $keyb64 = $GKconfig['key'];
            $ivb64 = $GKconfig['iv'];
            $authgroupid = $GKconfig['authgroupid'];
        }
        
        $data = json_decode(file_get_contents('php://input'), true);
        
        if ($data['authGroupId'] == $authgroupid ) {
            $key = base64_decode($keyb64);
            $iv  = base64_decode($ivb64);
            try {
                $msgcrypt = base64_decode($data['data']);
                $output = openssl_decrypt($msgcrypt, 'aes-256-cfb8', $key, 1, $iv);
                $dataReturn=json_decode($output,true);
            } catch (Exception $e) {
                throw $e; // 'Error decrypting: ',  $e->getMessage(), "\n";
            }
            
            return $dataReturn;
            
        }   
    }
    
    // $eventResponse = GOOD or BAD
    function resolveEvent($eventId, $token, $eventResponse)
    {
        $GKconfig = $this->GKconfig;
        $guardianKeyWS = $this->api_url+'/resolveevent';
        $tmpdata = new stdClass();
        $tmpdata->eventid = $eventId;
        $tmpdata->token = $token;
        $tmpdata->action = $eventResponse;
        $data = $this->_json_encode($tmpdata);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($ch, CURLOPT_URL, $guardianKeyWS);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data)
        ));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $return = curl_exec($ch);
        curl_close($ch);
        return $return;
    }
    
    function getEvent($eventId, $token)
    {
        $GKconfig = $this->GKconfig;
        $guardianKeyWS = $this->api_url+'/getevent';
        $tmpdata = new stdClass();
        $tmpdata->eventid = $eventId;
        $tmpdata->token = $token;
        $data = $this->_json_encode($tmpdata);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($ch, CURLOPT_URL, $guardianKeyWS);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($data)
        ));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $return = curl_exec($ch);
        curl_close($ch);
        return json_decode($return);
    }
    
    
}
?>
