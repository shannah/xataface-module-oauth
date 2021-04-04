<?php
class actions_oauth1_login {
    public function handle($params) {
        $app =& Dataface_Application::getInstance();
        $app->_conf['show_login_error_message'] = true;
        $oauth = Dataface_ModuleTool::getInstance()->loadModule("modules_oauth");
        $query =& $app->getQuery();
        $serviceName = @$query['service'];
        if (!$serviceName) {
            $_SESSION['-msg'] = "service GET parameter is required for oauth login";
            throw new Exception("service GET parameter is required for oauth login");
        }
        
        
        $serviceConfig = & $oauth->getServiceConfig($serviceName);
        if (!isset($serviceConfig)) {
            $_SESSION['-msg'] = "OAuth Service ".$serviceName." could not be found.";
            throw new Exception("OAuth Service ".$serviceName." could not be found.");
        }
        if (!isset($serviceConfig['client_id'])) {
            $_SESSION['-msg'] = "OAuth service doesn't specify a client id";
            throw new Exception("OAuth service doesn't specify a client_id");
        }
        
        if (!isset($serviceConfig['client_secret'])) {
            $_SESSION['-msg'] = "OAuth service doesn't specify a client secret";
            throw new Exception("OAuth service doesn't specify a client secret");
        }
        
        if (!isset($serviceConfig['request_token_url'])) {
            $_SESSION['-msg'] = "OAuth service doesn't specify a request_token_url";
            throw new Exception("OAuth service doesn't specify a request_token_url");
        }
        
        if (!isset($serviceConfig['authorize_url'])) {
            $_SESSION['-msg'] = "OAuth service doesn't specify a authorize_url";
            throw new Exception("OAuth service doesn't specify a authorize_url");
        }
        
        $app->startSession();
        $res = $oauth->post($serviceName, $serviceConfig['request_token_url'], array(
            'oauth_callback' => df_absolute_url(DATAFACE_SITE_HREF.'?-action=oauth1_callback&service='.urlencode($serviceName))
        ), false);
        
        if (df_http_response_code() < 200 and df_http_response_code() > 299) {
            $_SESSION['-msg'] = "Request token failed.  Please check your OAuth configuration for service $serviceName";
            throw new Exception("Request token failed with code ".df_http_response_code().". Check yout OAuth configuration.");
        }
        //print_r($res);exit;
        parse_str($res, $oauthData);
        //print_r($oauthData);
        
        
        $app->redirect($serviceConfig['authorize_url'].'?oauth_token='.urlencode($oauthData['oauth_token']));
        exit;

            
    }
}
