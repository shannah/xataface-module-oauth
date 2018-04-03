<?php
class actions_oauth2_callback {
    public function handle($params) {
        $app =& Dataface_Application::getInstance();
        $app->_conf['show_login_error_message'] = true;
        $mod =& Dataface_ModuleTool::getInstance()->loadModule('modules_oauth');
        $query =& $app->getQuery();
        $auth =& Dataface_AuthenticationTool::getInstance();
        //if ($auth->isLoggedIn()) {
        //    throw new Exception("You are already logged in");
        //}
        if (!@$query['service']) {
            throw new Exception("No service was specified");
        }
        if (@$query['code'] and @$query['state']) {
            // It was a success
            $app->startSession();
            $state = $_SESSION['oauth2_state'];
            if ($state != $query['state']) {
                $_SESSION['-msg'] = "OAuth Login failed.  State doesn't match";
                return Dataface_Error::permissionDenied("State doesn't match");
            }
            
            $serviceName = $query['service'];
            $serviceConfig = $mod->getServiceConfig($serviceName);
            if (!$serviceConfig) {
                throw new Exception("No configuration found for this service");
            }
            
            if (!@$serviceConfig['url']) {
                throw new Exception("No url supplied for this service");
            }
            
            $url = $serviceConfig['request_token_url'];
            $res = df_http_post($url, array(
                'grant_type' => 'authorization_code',
                'code' => $query['code'],
                
                'client_id' => $serviceConfig['client_id'],
                'client_secret' => $serviceConfig['client_secret'],
                'redirect_uri' => df_absolute_url(DATAFACE_SITE_HREF.'?-action=oauth2_callback&service='.urlencode($serviceName))//,
                //'HTTP_HEADERS' => 'Host: www.linkedin.com'."\r\n"
            ), true);
            //print_r($res);exit;
            if ($res and @$res['access_token']) {
                // This was a successful login
                $mod->setOauthToken($serviceName, $res['access_token'], null, true);
                //$_SESSION[$serviceName.'_access_token'] = $res['access_token'];
                $_SESSION[$serviceName.'_access_token_response'] = $res;
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
                            header('Location: '.DATAFACE_SITE_HREF);
                            exit;
                        } else {
                            $_SESSION['-msg'] = "Logged into ".$serviceName." but attempt to link profile failed.";
                            header('Location: '.DATAFACE_SITE_HREF);
                            exit;
                        }
                    } else if ($idColumn and $serviceUserId) {
                        $user = $auth->getLoggedInUser();
                        if ($user->val($idColumn) != $serviceUserId) {
                            $user->setValue($idColumn, $serviceUserId);
                            $res = $user->save();
                            if (PEAR::isError($res)) {
                                $_SESSION['-msg'] = "Login succeeded, but failed to link profile. ".$res->getMessage();
                                header('Location: '.DATAFACE_SITE_HREF);
                                exit;
                            }
                        }
                        $_SESSION['-msg'] = 'Successfully linked '.$serviceName.' account to your application user account';
                        header('Location: '.DATAFACE_SITE_HREF);
                        exit;
                            
                        
                    } else {
                        $_SESSION['-msg'] = 'Login to '.$serviceName.' succeeeded but you were already logged in.';
                        header('Location: '.DATAFACE_SITE_HREF);
                        exit;
                    }
                } 
                $user = $mod->getUser($serviceName);
                if (isset($user)) {
                    if ($user and $user->val($auth->usernameColumn)) {
                        $_SESSION['UserName'] = $user->val($auth->usernameColumn);
                    } else {
                        $_SESSION['-msg'] = 'Login to '.$serviceName.' succeeded but failed to complete login because the found user account has no username';
                        header('Location: '.DATAFACE_SITE_HREF);
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
                if (strpos($url, 'oauth2_callback') !== false) {
                    $url = DATAFACE_SITE_HREF;
                }
                
                $_SESSION['-msg'] = "Logged in successfully using ".$serviceName;
                header('Location: '.$url);
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

