<?php
class actions_oauth2_login {
    public function handle($params) {
        $app =& Dataface_Application::getInstance();
        $app->_conf['show_login_error_message'] = true;
        $mod = Dataface_ModuleTool::getInstance()->loadModule('modules_oauth');
        $query =& $app->getQuery();
        $serviceName = @$query['service'];
        if (!$serviceName) {
            throw new Exception("service GET parameter is required for oauth login");
        }
        
        $serviceConfig =& $mod->getServiceConfig($serviceName);
        if (!isset($serviceConfig)) {
            throw new Exception("OAuth Service ".$serviceName." could not be found.");
        }
        
        if (!isset($serviceConfig['client_id'])) {
            throw new Exception("OAuth service doesn't specify a client_id");
        }
        
        if (!isset($serviceConfig['url'])) {
            throw new Exception("OAuth service doesn't specify a url");
        }
        
        $app->startSession();
        $auth = Dataface_AuthenticationTool::getInstance();
        if ($auth->isLoggedIn()) {
            throw new Exception("You are already logged in");
        }
        $_SESSION['oauth2_state'] = xf_db_fetch_row(df_q("select UUID()"))[0];
        $url = $serviceConfig['url'];
        //if (!preg_match('#/authorization$#', $url)) {
        //    if (!preg_match('#/$#', $url)) {
        //        $url .= '/';
        //    }
        //    $url .= 'authorization';
        //}
        
        $url .= '?response_type=code&client_id='.urlencode($serviceConfig['client_id'])
                .'&state='.urlencode($_SESSION['oauth2_state'])
                .'&redirect_uri='.urlencode(df_absolute_url(DATAFACE_SITE_HREF.'?-action=oauth2_callback&service='.urlencode($serviceName)))
                ;
        if (@$serviceConfig['scope']) {
            $url .= '&scope='.urlencode($serviceConfig['scope']);
        }
        
        header('Location: '.$url);
        exit;
            
    }
}
