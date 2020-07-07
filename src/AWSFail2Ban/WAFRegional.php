<?php

namespace AWSFail2Ban;

require_once 'AbstractResource.php';

class WAFRegional extends AbstractResource {

    const ITERATION_MAX = 1000;

    const CMD_CHANGE_TOKEN                  = 'aws waf-regional get-change-token';
    const CMD_GET_IP_SET                    = 'aws waf-regional get-ip-set';
    const CMD_UPDATE_IP_SET                 = 'aws waf-regional update-ip-set --change-token %s --updates \'%s\'';
    const CMD_UPDATE_IP_SET_ACTION_INSERT   = 'Action="INSERT",IPSetDescriptor={Type="%s",Value="%s"}';
    const CMD_UPDATE_IP_SET_ACTION_DELETE   = 'Action="DELETE",IPSetDescriptor={Type="%s",Value="%s"}';

    /**
     * Appends --ip-set-id to filter commands
     *
     * @param $cmd
     * @return mixed|string
     */
    protected static function cmdFilter($cmd){
        return trim($cmd) . ' --ip-set-id ' . static::$aws_resource_id;
    }

    /**
     * Get all IPs that are banned from the IPSet
     *
     * @return array|mixed
     * @throws \Exception
     */
    public static function getAllIpsBanned($ip_only = false) {

        // build cmd
        $cmd = static::CMD_GET_IP_SET;

        // filters by ip-set-it
        $cmd = static::cmdFilter($cmd);

        // adds region and other options
        $cmd = static::cmdOptions($cmd);

        // execute and get response
        $response = json_decode(shell_exec($cmd), 1);

        // validations
        if( !isset($response['IPSet']) ){
            echo 'IPSet not returned in response' . PHP_EOL;
            exit(1);
        }

        if( empty($response['IPSet']) ){
            echo 'No IPSet found for ' . static::$aws_resource_id . '. Are you in the correct region?' . PHP_EOL;
            exit(1);
        }

        /*if( $response['IPSet']['IPSetId'] !== static::$aws_resource_id ){
            echo 'Returned IPSetId of ' . $response['IPSet']['IPSetId'] . ' doesn\'t match configured IPSetId of ' . static::$aws_resource_id . PHP_EOL;
            exit(1);
        }*/

        // extract LockToken if present
        if( isset($response['LockToken']) ) {
            static::$change_token = $response['LockToken'];
        }

        if(
            $ip_only === true
            && static::class === WAFRegional::class
        ){

            return array_reduce($response['IPSet']['IPSetDescriptors'], function($banned, $entry){
                array_push($banned, $entry['Value']);
            }, []);

        }elseif( $ip_only === true ) {
            return $response['IPSet']['Addresses'];
        }elseif( static::class === WAFRegional::class ){
            return $response['IPSet']['IPSetDescriptors'];
        }else{
            return $response['IPSet'];
        }

    }

    /**
     *
     *
     * @param $ip
     * @return bool
     * @throws \Exception
     */
    public static function checkIfBanned($ip) {

        // in case a formatted ip address is passed pick out address_cidr
        if(is_array($ip)){
            $ip = $ip['address_cidr'];
        }

        if(in_array(static::formatIp($ip, true), static::getAllIpsBanned(true))){
            return true;
        }else{
            return false;
        }

    }

    public static function unbanAll(){

        $allIps = static::getAllIpsBanned();
        $allIpsCount = count($allIps);

        while($allIpsCount > 0){

            try{

                $allPosition = 0;
                $iterationMax = static::ITERATION_MAX;
                $iterationLoop = -1;

                while ( $allPosition < $allIpsCount ) {

                    $iterationLoop++;
                    $iterationPosition = 0;
                    $iterationIPSetDescriptors = [];

                    while( $iterationPosition < $iterationMax ){

                        if( !isset($allIps[$allPosition]) ){
                            continue;
                        }else{
                            $iterationIPSetDescriptors[] = sprintf(
                                static::CMD_UPDATE_IP_SET_ACTION_DELETE,
                                $allIps[$allPosition]['Type'],
                                $allIps[$allPosition]['Value']
                            );
                        }

                        $iterationPosition++;
                        $allPosition++;

                    }

                    // each change requires a change token
                    $change_token = static::getChangeToken();

                    // execute api call
                    echo 'Unbanning ' . ($iterationMax * $iterationLoop) . ' to ' . ($iterationMax * $iterationLoop + $iterationMax) . ' of ' . $allIpsCount . ' banned IPs' . PHP_EOL;

                    // construct command to unban ip address
                    $cmd = sprintf(
                        static::CMD_UPDATE_IP_SET,
                        $change_token,
                        implode(',', $iterationIPSetDescriptors)
                    );

                    // filters by ip-set-it
                    $cmd = static::cmdFilter($cmd);

                    // adds region and other options
                    $cmd = static::cmdOptions($cmd);

                    // unban
                    shell_exec($cmd);

                }

            // an exception could include the change token being
            // invalidated
            } catch (\Exception $e) {

                echo $e->getMessage() . PHP_EOL;
                // note: let's keep going...
                //exit(1);

            }

            // let's fetch the ips again to make sure we are
            // reliability removing all banned ip addresses
            $allIps = static::getAllIpsBanned(false);
            $allIpsCount = count($allIps);

        }

    }

    /**
     * @return mixed
     */
    public static function getChangeToken(){

        // aws cmd to add IP
        $cmd = static::CMD_CHANGE_TOKEN;

        // adds region and other options
        $cmd = static::cmdOptions($cmd);

        // convert to json
        $response = json_decode(shell_exec($cmd), 1);

        // no change token
        if( !isset($response['ChangeToken']) ){
            echo 'unable to get ChangeToken' . PHP_EOL;
            exit(1);
        }

        // return change-token
        echo 'change-token=' . $response['ChangeToken'] . PHP_EOL;
        return $response['ChangeToken'];
    }

    /**
     * Unban an IP by removing it from the IPSet
     *
     * @param $ip
     * @return mixed|void
     */
    public static function unban($ip) {

        $banned = true;

        // due to the possibility of the change-token expiring before
        // we can unban the ip, we will verify if the ip was actually
        // unbanned and repeat if necessary until this script times
        // out
        while( $banned === true ){

            try{

                // each change requires a change token
                $change_token = static::getChangeToken();

                // make sure IP is formatted for AWS API
                $ip = static::formatIp($ip);

                $action = sprintf(
                    static::CMD_UPDATE_IP_SET_ACTION_DELETE,
                    $ip['type'],
                    $ip['address_cidr']
                );

                $cmd = sprintf(
                    static::CMD_UPDATE_IP_SET,
                    $change_token,
                    $action
                );

                // filters by ip-set-it
                $cmd = static::cmdFilter($cmd);

                // adds region and other options
                $cmd = static::cmdOptions($cmd);

                // execute api call
                echo "Unbanning ${ip['address_cidr']}" . PHP_EOL;
                shell_exec($cmd);

                // success
                $banned = static::checkIfBanned($ip['address_cidr']);

            }catch (\Exception $e){
                echo $e->getMessage() . PHP_EOL;
            }

        }

    }

    /**
     * Ban an IP by adding to the IPSet
     *
     * @param $ip
     * @return mixed|void
     */
    public static function ban($ip) {

        // each change requires a change token
        $change_token = static::getChangeToken();

        // make sure IP is formatted for AWS API
        $ip = static::formatIp($ip);

        $insert_action = sprintf(
            static::CMD_UPDATE_IP_SET_ACTION_INSERT,
            $ip['type'],
            $ip['address_cidr']
        );

        $cmd = sprintf(
            static::CMD_UPDATE_IP_SET,
            $change_token,
            $insert_action
        );

        // filters by ip-set-it
        $cmd = static::cmdFilter($cmd);

        // adds region and other options
        $cmd = static::cmdOptions($cmd);

        echo "Banning ${ip['address_cidr']}" . PHP_EOL;

        // execute api call
        shell_exec($cmd);

    }

}
