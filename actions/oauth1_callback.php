<?php
class actions_oauth1_callback {
    
    public function handle($params) {
        try {
            $out = $this->handle1($params);
            if (PEAR::isError($out) and !isset($_SESSION['-msg'])) {
                $_SESSION['-msg'] = $out->getMessage();
                Dataface_Application::getInstance()->addMessage($out->getMessage());
            }
            return $out;
        } catch (Exception $ex) {
            if (!isset($_SESSION['-msg'])) {
                $_SESSION['--msg'] = $ex->getMessage();
                
            }
            throw $ex;
        }
    }
    
    private function handle1($params) {
        
        $app =& Dataface_Application::getInstance();
        $app->_conf['show_login_error_message'] = true;
        $mod = Dataface_ModuleTool::getInstance()->loadModule('modules_oauth');
        $query =& $app->getQuery();
        $auth =& Dataface_AuthenticationTool::getInstance();
        if (!@$query['service']) {
            $app->startSession();
            $_SESSION['-msg'] = "No service was specified";
            throw new Exception("No service was specified");
        }
        if (@$query['oauth_verifier'] and @$query['oauth_token']) {
            
            
            // It was a success
            $app->startSession();
            
            $serviceName = $query['service'];
            $serviceConfig = $mod->getServiceConfig($serviceName);
            
            if (!$serviceConfig) {
                throw new Exception("No configuration found for this service");
            }
            
            if (!@$serviceConfig['access_token_url']) {
                throw new Exception("No url supplied for this service");
            }
            
            $res = $mod->post($serviceName, $serviceConfig['access_token_url'], array(
                'oauth_token' => $query['oauth_token'],
                'oauth_verifier' => $query['oauth_verifier']
            ), false);
            if (df_http_response_code() < 200 or df_http_response_code() > 299) {
                //echo "here";exit;
                $_SESSION['-msg'] = "Request for access token failed.  Please check your error log for details";
                if (@$app->_conf['debug']) {
                    error_log("Request to ".$serviceConfig['access_token_url']." failed with code ". df_http_response_code());
                    error_log($res);
                }
                return Dataface_Error::permissionDenied("Request for access token failed");
            }
            parse_str($res, $data);
            $res = $data;
            
            
            //print_r($res);exit;
            if ($res and @$res['oauth_token']) {
                // This was a successful login
                if (!$mod->setOauthToken($serviceName, $res['oauth_token'], $res['oauth_token_secret'], true)) {
                    $_SESSION['-msg'] = "Received oauth_token but failed to save it for some reason.  Check your error log.";
                    return Dataface_Error::permissionDenied("There was a problem saving the token.  Check your error log.");
                }
                $_SESSION[$serviceName.'_access_token_response'] = $res;
                $delegate = $app->getDelegate();
                
                $userData = $mod->fetchUserData($serviceName);

                if (!isset($userData)) {
                    $_SESSION['-msg'] = 'Received oauth_token but failed to fetch user info.  Check your error log.';
                    throw new Exception("Failed to fetch user data for service $serviceName");
                }
                
                $serviceUserId = $mod->extractServiceUserIdFromUserData($serviceName, $userData);
                if (!isset($serviceUserId)) {
                    $_SESSION['-msg'] = 'Failed to extract userID from user info for service '.$serviceName;
                    throw new Exception("Failed to extract user ID for service $serviceName");
                }
                $mod->setServiceUserId($serviceName, $serviceUserId);
                
                
                
                $auth = Dataface_AuthenticationTool::getInstance();
                $usersTable = Dataface_Table::loadTable($auth->usersTable);
                $idColumn = $mod->getServiceUserIdColumn($serviceName);
                //$serviceUserId = $mod->getServiceUserId($serviceName);
                if ($auth->isLoggedIn()) {
                    // We are already logged in, so we'll just link it to our account
                    if ($delegate and method_exists($delegate, 'oauth_link_profile')) {
                        $res = $delegate->oauth_link_profile($serviceName, $auth->getLoggedInUser());
                        if (PEAR::isError($res)) {
                            $_SESSION['-msg'] = 'Failed to link profile: '.$res->getMessage();
                            return $res;
                        }
                        if ($res) {
                            $_SESSION['-msg'] = 'Profile was successfully linked to your '.$serviceName.' profile.';
                            $app->redirect(DATAFACE_SITE_HREF);
                            exit;
                        } else {
                            $_SESSION['-msg'] = "Logged into ".$serviceName." but attempt to link profile failed.";
                            $app->redirect(DATAFACE_SITE_HREF);
                            exit;
                        }
                    } else if ($idColumn and $serviceUserId) {
                        $user = $auth->getLoggedInUser();
                        if ($user->val($idColumn) != $serviceUserId) {
                            $user->setValue($idColumn, $serviceUserId);
                            $res = $user->save();
                            if (PEAR::isError($res)) {
                                $_SESSION['-msg'] = "Login succeeded, but failed to link profile. ".$res->getMessage();
                                $app->redirect(DATAFACE_SITE_HREF);
                                exit;
                            }
                        }
                        $_SESSION['-msg'] = 'Successfully linked '.$serviceName.' account to your application user account';
                        $app->redirect(DATAFACE_SITE_HREF);
                        exit;
                            
                        
                    } else {
                        $_SESSION['-msg'] = 'Login to '.$serviceName.' succeeeded but you were already logged in.';
                        $app->redirect(DATAFACE_SITE_HREF);
                        exit;
                    }
                } 
                $user = $mod->getUser($serviceName);
                if (isset($user)) {
                    if ($user and $user->val($auth->usernameColumn)) {
                        $_SESSION['UserName'] = $user->val($auth->usernameColumn);
                    } else {
                        $_SESSION['-msg'] = 'Login to '.$serviceName.' succeeded but failed to complete login because the found user account has no username';
                        $app->redirect(DATAFACE_SITE_HREF);
                        exit;
                    }
                } else {
                    $user = $mod->createUser($serviceName, $userData);
                    if (PEAR::isError($user)) {
                        $_SESSION['-msg'] = "Login failed due to error creating user";
                        error_log($user->getMessage());
                        return $user;
                    }
                    if ($user) {
                        $_SESSION['UserName'] = $user->val($auth->usernameColumn);
                    }
                    
                    
                }
                
                
                
                if (!@$_SESSION['UserName']) {
                    //echo "here";exit;//
                    $_SESSION['--msg'] = "OAuth Login was successful, but you don't have an account in this application.";
                    return Dataface_Error::permissionDenied("You do not have an account in this application.");
                }
                
                
                $url = DATAFACE_SITE_HREF.'?--msg='.urlencode("You are now logged in");
                if (isset($_SESSION['-redirect'])) {
                    $url = $_SESSION['-redirect'];
                    unset($_SESSION['-redirect']);
                    df_append_query($url, array('--msg'=> 'You are now logged in'));
                }
                if (strpos($url, 'oauth1_callback') !== false) {
                    $url = DATAFACE_SITE_HREF;
                }
                
                $_SESSION['-msg'] = "Logged in successfully using ".$serviceName;
                $app->redirect($url);
            } else {
                $_SESSION['-msg'] = "OAuth login failed.  Could not validate access token with service ".$serviceName;
                return Dataface_Error::permissionDenied("Failed to validate access token with service ".$serviceName);
            }
            
            
        } else {
            $_SESSION['-msg'] = "OAuth login failed.  ".$query['error_description'];
            return Dataface_Error::permissionDenied($query['error_description']);
        }
    }
}

