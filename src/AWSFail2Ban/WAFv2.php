<?php

namespace AWSFail2Ban;

require_once 'WAFRegional.php';

class WAFv2 extends WAFRegional {

    const CMD_CHANGE_TOKEN                  = '';
    const CMD_GET_IP_SET                    = 'aws wafv2 get-ip-set';
    const CMD_UPDATE_IP_SET                 = 'aws wafv2 update-ip-set --lock-token %s --addresses %s';
    //const CMD_UPDATE_IP_SET_ACTION_INSERT   = 'Action="INSERT",IPSetDescriptor={Type="%s",Value="%s"}';
    //const CMD_UPDATE_IP_SET_ACTION_DELETE   = 'Action="DELETE",IPSetDescriptor={Type="%s",Value="%s"}';

    /**
     * Appends --scope and --id
     *
     * @param $cmd
     * @return mixed|string
     */
    protected static function cmdFilter($cmd){
        return trim($cmd) . ' --scope REGIONAL --name ' . self::$name . ' --id ' . static::$aws_resource_id;
    }

    /**
     * This isn't needed with wafv2
     *
     * @return mixed
     */
    public static function getChangeToken(){
        return self::$change_token;
    }

    /**
     * Ban an IP by adding to the IPSet
     *
     * @param $ip
     * @return mixed|void
     */
    public static function ban($ip) {

        // get all ip addresses
        $ip_addresses = self::getAllIpsBanned(true);

        // each change requires a change token
        $change_token = static::getChangeToken();

        // make sure IP is formatted for AWS API
        $ip = static::formatIp($ip, true);

        // add new ip address to existing ip addresses
        array_push($ip_addresses, $ip);

        $cmd = sprintf(
            static::CMD_UPDATE_IP_SET,
            $change_token,
            implode(
                ' ',
                $ip_addresses
            )
        );

        // filters by ip-set-it
        $cmd = static::cmdFilter($cmd);

        // adds region and other options
        $cmd = static::cmdOptions($cmd);

        echo "Banning ${ip}" . PHP_EOL;

        // execute api call
        shell_exec($cmd);

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

                // get all ip addresses
                $ip_addresses = self::getAllIpsBanned(true);

                // each change requires a change token
                $change_token = static::getChangeToken();

                // make sure IP is formatted for AWS API
                $ip = static::formatIp($ip, true);

                // remove ip from all ip addresses
                $ip_addresses_filtered = array_filter($ip_addresses, function($value) use ($ip) {
                    return ( $value !== $ip );
                });

                $cmd = sprintf(
                    static::CMD_UPDATE_IP_SET,
                    $change_token,
                    implode(
                        ' ',
                        $ip_addresses_filtered
                    )
                );

                // filters by ip-set-it
                $cmd = static::cmdFilter($cmd);

                // adds region and other options
                $cmd = static::cmdOptions($cmd);

                // execute api call
                echo "Unbanning ${ip}" . PHP_EOL;
                shell_exec($cmd);

                // success
                $banned = static::checkIfBanned($ip);

            }catch (\Exception $e){
                echo $e->getMessage() . PHP_EOL;
            }

        }

    }

    public static function unbanAll(){

        $allIps = static::getAllIpsBanned(true);
        $allIpsCount = count($allIps);

        while($allIpsCount > 0){

            try{

                // each change requires a change token
                $change_token = static::getChangeToken();

                // execute api call
                echo 'Unbanning all ' . $allIpsCount . ' banned IPs' . PHP_EOL;

                // construct command to unban ip address
                $cmd = sprintf(
                    static::CMD_UPDATE_IP_SET,
                    $change_token,
                    ''
                );

                // filters by ip-set-it
                $cmd = static::cmdFilter($cmd);

                // adds region and other options
                $cmd = static::cmdOptions($cmd);

                // unban
                shell_exec($cmd);

                // an exception could include the change token being
                // invalidated
            } catch (\Exception $e) {

                echo $e->getMessage() . PHP_EOL;
                // note: let's keep going...
                //exit(1);

            }

            // let's fetch the ips again to make sure we are
            // reliability removing all banned ip addresses
            $allIps = static::getAllIpsBanned(true);
            $allIpsCount = count($allIps);

        }

    }

}
