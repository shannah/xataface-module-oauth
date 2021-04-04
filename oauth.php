<?php

class modules_oauth {

    /**
     * @brief The base URL to the datepicker module.  This will be correct whether it is in the 
     * application modules directory or the xataface modules directory.
     *
     * @see getBaseURL()
     */
    private $baseURL = null;

    /**
     * @brief Returns the base URL to this module's directory.  Useful for including
     * Javascripts and CSS.
     *
     */
    public function getBaseURL() {
        if (!isset($this->baseURL)) {
            $this->baseURL = Dataface_ModuleTool::getInstance()->getModuleURL(__FILE__);
        }
        return $this->baseURL;
    }

    
    public function __construct() {
        $app = Dataface_Application::getInstance();
        $conf =& $app->_conf;
        $s = DIRECTORY_SEPARATOR;
        $app->registerEventListener('beforeHandleRequest', array($this, 'beforeHandleRequest'));
    }
    
    
    
    /**
     * Issues an HTTP post request for the specified service.
     * @param type $serviceName
     * @param type $url
     * @param array $params
     * @param type $json
     * @return type
     */
    public function post($serviceName, $url, $params=array(), $json=true) {
        $serviceConfig =& $this->getServiceConfig($serviceName);
        if (!$serviceConfig or @$serviceConfig['version'] !== 1) {
            return df_http_post($url, $params, $json);
        }
        $authHeader = $this->generateAuthorizationHeader('POST', $url, $serviceName, $params);
        $headers = '';
        if (isset($params['HTTP_HEADERS'])) {
            $headers = $params['HTTP_HEADERS'];
            
        }
        $headers .= 'Authorization: '.$authHeader."\r\n";
        $params['HTTP_HEADERS'] = $headers;
        //print_r($headers);exit;
        //print_r($params);
        return df_http_post($url, $params, $json);
    }
    
    /**
     * Issues an HTTP get request for the specified service.
     * @param type $serviceName
     * @param type $url
     * @param string $headers
     * @param type $json
     * @return type
     */
    public function get($serviceName, $url, $headers='', $json=true) {
        $serviceConfig =& $this->getServiceConfig($serviceName);
        if (!$serviceConfig or @$serviceConfig['version'] !== 1) {
            return df_http_post($url, $params, $json);
        }
        $authHeader = $this->generateAuthorizationHeader('GET', $url, $serviceName, array());
        
        $headers .= 'Authorization: '.$authHeader."\r\n";
        //$params['HTTP_HEADERS'] = $headers;
        //print_r($params);
        return df_http_get($url, $headers, $json);
    }
    
    /**
     * Fetches the user data for the given service name.
     * @param type $serviceName
     * @return type
     */
    public function fetchUserData($serviceName) {
        $event = new StdClass;
        $event->service = $serviceName;
        $event->out = null;

        Dataface_Application::getInstance()->fireEvent('oauth_fetch_user_data', $event);
        return $event->out;
        
    }
    
    /**
     * Extracts the user ID for the specified service from the given $userData data
     * structure, which would have been returned from {@link #fetchUserData}
     * @param type $serviceName
     * @param type $userData
     * @return type
     */
    public function extractServiceUserIdFromUserData($serviceName, $userData) {
        //echo "about to extact proper"
        $props = $this->extractUserPropertiesFromUserData($serviceName, $userData);
        return $props['id'];
    }
    
    public function extractUserPropertiesFromUserData($serviceName, $userData) {
        $event = new StdClass;
        $event->service = $serviceName;
        $event->userData = $userData;
        $event->out = null;

        Dataface_Application::getInstance()->fireEvent('oauth_extract_user_properties_from_user_data', $event);
        return $event->out;
    }
    
    
    
    /**
     * Gets the service-specific User ID for the given service.
     * @param type $serviceName
     * @return type
     */
    public function getServiceUserId($serviceName) {
        if (isset($_SESSION[$serviceName.'_user_id'])) {
            return $_SESSION[$serviceName.'_user_id'];
        }
        return null;
    }
    
    /**
     * Sets the service-specific User ID for the given service.
     * @param type $serviceName
     * @param type $userId
     */
    public function setServiceUserId($serviceName, $userId) {
        $_SESSION[$serviceName.'_user_id'] = $userId;
    }
    
    /**
     * Gets the name of the column in the users table that stores the service-specific
     * user ID for the given service.
     * @param type $serviceName
     * @return type
     */
    public function getServiceUserIdColumn($serviceName) {
        $serviceConfig =& $this->getServiceConfig($serviceName);
        if (!isset($serviceConfig)) {
            return null;
        }
        if (isset($serviceConfig['users_table.id_column'])) {
            return $serviceConfig['users_table.id_column'];
        }
        
        $usersTable = Dataface_AuthenticationTool::getInstance()->getUsersTable();
        $fields =& $usersTable->fields();
        if (isset($fields[$serviceName.'_id'])) {
            return $serviceName.'_id';
        }
        return null;
        
    }
    
    /**
     * Creates a new user account based on the user data retrieved from the specified
     * service.  $userData would have been obtained from fetchUserData.
     * @param type $serviceName
     * @param type $userData
     * @return type
     */
    public function createUser($serviceName, $userData) {
        $app = Dataface_Application::getInstance();
        $delegate = $app->getDelegate();
        if (method_exists($delegate, 'oauth_create_user')) {
            return $delegate->oauth_create_user($serviceName, $userData);
        } else {
            //echo "here";exit;
            $serviceConfig =& $this->getServiceConfig($serviceName);
            if (@$serviceConfig['autocreate']) {
                //echo "Attempting to autocreate ";exit;
                $props = $this->extractUserPropertiesFromUserData($serviceName, $userData);
                $auth = Dataface_AuthenticationTool::getInstance();
                $idColumn = $this->getServiceUserIdColumn($serviceName);

                $index = 0;
                $user = new Dataface_Record($auth->usersTable, 
                        array(
                            'name' => $props['username'],
                            $idColumn => $props['id']
                        )
                );
                $usernameBase = $user->val('name');
                $username = $usernameBase . '@' . $serviceName;

                while ($auth->findUserByUsername($username)) {
                    $index++;
                    $username = $usernameBase . $index . '@' . $serviceName;

                }
                $user->setValue($auth->usernameColumn, $username);
                $user->pouch['oauth.service'] = $serviceName;
                $user->pouch['oauth.user.properties'] = $props;
                $user->pouch['oauth.user.data'] = $userData;
                $res = $user->save();
                if (PEAR::isError($res)) {
                    throw new Exception("Failed to save ".$serviceName." user ".$res->getMessage());
                }

                return $user;
            } else {
                return null;
            }
        }
    }
    
    /**
     * Gets the record from the users table corresponding to the current user
     * from the specified service.
     * @param type $serviceName
     * @return type
     */
    public function getUser($serviceName) {
        $app = Dataface_Application::getInstance();
        $delegate = $app->getDelegate();
        $serviceUserId = $this->getServiceUserId($serviceName);
        if (!isset($serviceUserId)) {
            return null;
        }
        $auth = Dataface_AuthenticationTool::getInstance();
        $serviceUserIdColumn = $this->getServiceUserIdColumn($serviceName);
        
        
        if ($delegate and method_exists($delegate, 'oauth_get_user')) {
            
            return $delegate->oauth_get_user($serviceName, $serviceUserId);
            
        } else { 
            if (isset($serviceUserIdColumn)) {
                return $auth->findUser(array($serviceUserIdColumn => '='.$serviceUserId));
                
            }
            return null;

        }
    }
    
    /**
     * Generates the Oauth1 authorization header for an HTTP request.
     * @param type $method
     * @param type $url
     * @param type $serviceName
     * @param type $postParams
     * @return string
     */
    public function generateAuthorizationHeader($method, $url, $serviceName, $postParams=array()) {
        
        $app = Dataface_Application::getInstance();
        $baseUrl = $url;
        if (strpos($baseUrl, '?') !== false) {
            $baseUrl = substr($baseUrl, 0, strpos($baseUrl, '?'));
        }
        $queryString = substr($url, strlen($baseUrl));
        $params = array();
        foreach ($postParams as $k=>$v) {
            $params[$k] = $v;
        }
        if ($queryString) {
            if ($queryString[0] == '?') {
                $queryString = substr($queryString, 1);
            }
            parse_str($queryString, $tmpParams);
            foreach ($tmpParams as $k=>$v) {
                $params[$k] = $v;
            }
        }
        
        $serviceConfig =& $app->_conf['oauth_'.$serviceName];
        $isTokenRequest = $serviceConfig['request_token_url'] == $url;
        
        $params['oauth_consumer_key'] = $serviceConfig['client_id'];
        $params['oauth_nonce'] = md5(mt_rand());
        $params['oauth_signature_method'] = 'HMAC-SHA1';
        $params['oauth_timestamp'] = time();
        $params['oauth_version'] = '1.0';
        //print_r($_SERVER);exit;
        //print_r($_SESSION);
        $oauthToken = $this->getOauthToken($serviceName);
        if (!isset($params['oauth_token']) and isset($oauthToken) and !$isTokenRequest) {
            $params['oauth_token'] = $oauthToken;
        }
        
        $tmp = array();
        foreach ($params as $k=>$v) {
            $tmp[rawurlencode($k)] = rawurlencode($v);
        }
        $params = $tmp;
        ksort($params);
        
        $paramString = '';
        $first = true;
        foreach ($params as $k=>$v) {
            if ($first) {
                $first = false;
            } else {
                $paramString .= '&';
            }
            $paramString .= $k . '=' . $v;
        }
        $baseUrl = $url;
        if (strpos($url, '?') !== false) {
            $baseUrl = substr($url, 0, strpos($url, '?'));
        }
        $signatureBase = strtoupper($method).'&'.rawurlencode($baseUrl).'&'.rawurlencode($paramString);
        //echo "Signature base: ".$signatureBase;exit;
            $signingKey = rawurlencode($serviceConfig['client_secret']).'&';
            $tokenSecret = $this->getOauthTokenSecret($serviceName);
            if (isset($tokenSecret) and !$isTokenRequest) {
                $signingKey .= rawurlencode($tokenSecret);
            }
            //echo "<br>Signing Key: ".$signingKey;exit;
            $signature = base64_encode(hash_hmac("sha1", $signatureBase, $signingKey, true));
    //echo "<br>Signature ".$signature;exit;
        $oauth_keys = array(
            'oauth_consumer_key', 'oauth_nonce', 'oauth_signature_method', 'oauth_timestamp', 'oauth_token', 'oauth_version', 'oauth_callback'
        );
        
        $auth_params = array();
        foreach ($oauth_keys as $k) {
            if (isset($params[$k])) {
                $auth_params[$k] = $params[$k];
            }
        }
        $auth_params['oauth_signature'] = rawurlencode($signature);
        
        $DST = 'OAuth ';
        $first = true;
        foreach ($auth_params as $k=>$v) {
            if ($first) {
                $first = false;
            } else {
                $DST .= ', ';
            }
            $DST .= $k.'="'.$v.'"';
        }
        //echo $DST;exit;
        return $DST;
        
                    
    }
    
    /**
     * Gets the service configuration for the given service.
     * @param type $serviceName
     * @return type
     */
    public function &getServiceConfig($serviceName) {
        $app =& Dataface_Application::getInstance();
        if (isset($app->_conf['oauth_'.$serviceName])) {
            return $app->_conf['oauth_'.$serviceName];
        }
        $null = null;
        return $null;
    }
    
    /**
     * Sets the oauth token and oauth token secret for the specified service to be
     * used in HTTP requests to the service.
     * @param type $serviceName
     * @param type $oauthToken
     * @param type $oauthTokenSecret
     * @param type $saveInSession
     * @return boolean
     */
    public function setOauthToken($serviceName, $oauthToken, $oauthTokenSecret, $saveInSession=false) {
        if ($saveInSession) {
            if (isset($oauthToken)) {
                $_SESSION[$serviceName.'_oauth_token'] = $oauthToken;
            } else {
                unset($_SESSION[$serviceName.'_oauth_token']);
            }
            
            if (isset($oauthTokenSecret)) {
                $_SESSION[$serviceName.'_oauth_token_secret'] = $oauthTokenSecret;
            } else {
                unset($_SESSION[$serviceName.'_oauth_token_secret']);
            }
            return true;
        } else {
            $serviceConfig =& $this->getServiceConfig($serviceName);
            if (isset($serviceConfig)) {
                $serviceConfig['oauth_token'] = $oauthToken;
                $serviceConfig['oauth_token_secret'] = $oauthTokenSecret;
                
                return true;
            } else {
                error_log("Attempt to set oauth_token for service ".$serviceName." failed because there is no config entry in the conf.ini file for oauth_".$serviceName);
                return false;
            }
        }
    }
    
    /**
     * Gets the current oauth token for the specified service.
     * @param type $serviceName
     * @return type
     */
    public function getOauthToken($serviceName) {
        $serviceConfig =& $this->getServiceConfig($serviceName);
        if (isset($serviceConfig) and isset($serviceConfig['oauth_token'])) {
            return $serviceConfig['oauth_token'];
        }
        if (isset($_SESSION[$serviceName.'_oauth_token'])) {
            return $_SESSION[$serviceName.'_oauth_token'];
        }
        return null;
    }
    
    /**
     * Gets the oauth token secret for the specified service.  Used only for oauth1
     * services.
     * @param type $serviceName
     * @return type
     */
    public function getOauthTokenSecret($serviceName) {
        $serviceConfig =& $this->getServiceConfig($serviceName);
        if (isset($serviceConfig) and isset($serviceConfig['oauth_token_secret'])) {
            return $serviceConfig['oauth_token_secret'];
        }
        if (isset($_SESSION[$serviceName.'_oauth_token_secret'])) {
            return $_SESSION[$serviceName.'_oauth_token_secret'];
        }
        return null;
    }
    
    /**
     * Event handler to be called before each request.  This parses the oauth actions
     * and populates the service configs.
     */
    public function beforeHandleRequest() {
        $app = Dataface_Application::getInstance();
        $conf =& $app->_conf;
        $s = DIRECTORY_SEPARATOR;
        $query =& $app->getQuery();
        if (true) { // We may need the oauth config anywhere in the app
        //if (@$query['-action'] == 'login' or 
        //        $query['-action'] == 'login_prompt' or 
        //        strpos($query['-action'], 'oauth_') !== false or 
        //        strpos($query['-action'], 'oauth1_') !== false or 
        //        strpos($query['-action'], 'oauth2_') !== false) {
            // Add the oauth actions
            $order = -1000;
            $prefix = 'oauth_';
            $at = Dataface_ActionTool::getInstance();
            $actions = $at->getActions(array('category' => 'login_actions'));
            
            $prefixLen = strlen($prefix);
            foreach (array_keys($actions) as $actionName) {
                if (strpos($actionName, 'oauth_') !== 0) {
                    continue;
                }
                
                $action =& $at->actions[$actionName];
                if (!isset($conf[$actionName])) {
                    $action['condition'] = "false";
                    continue;
                }
                if (@$action['oauth.authorize_url']) {
                    // If it has oauth.authorize_url then we assume oauth 1.0
                    if (!@$action['oauth.authorize_url']) {
                        $action['condition'] = "false";
                        continue;
                    }
                    if (!@$action['oauth.request_token_url']) {
                        $action['condition'] = "false";
                        continue;
                    }
                    $serviceConfig =& $conf[$actionName];
                    if (!@$serviceConfig['client_id'] or !@$serviceConfig['client_secret']) {
                        $action['condition'] = "false";
                        continue;
                    }
                    $serviceConfig['version'] = 1;
                    $serviceConfig['authorize_url'] = $action['oauth.authorize_url'];
                    $serviceConfig['request_token_url'] = $action['oauth.request_token_url'];
                    $serviceConfig['access_token_url'] = $action['oauth.access_token_url'];
                    $action['url'] =  DATAFACE_SITE_HREF . '?-action=oauth1_login&service='.urlencode(substr($actionName, strlen($prefix)));
                } else {
                    // We assume oauth 2.0 otherwise
                    if (!@$action['oauth.url']) {
                        $action['condition'] = 0;
                        continue;
                    }
                    $serviceConfig =& $conf[$actionName];
                    if (!@$serviceConfig['client_id'] or !@$serviceConfig['client_secret']) {
                        $action['condition'] = 0;
                        continue;
                    }

                    $serviceConfig['version'] = 2;
                    $serviceConfig['url'] = $action['oauth.url'];
                    $serviceConfig['request_token_url'] = $action['oauth.request_token_url'];
                    $action['url'] =  DATAFACE_SITE_HREF . '?-action=oauth2_login&service='.urlencode(substr($actionName, strlen($prefix)));

                }
            }
            
        }
        
        
    }


}
