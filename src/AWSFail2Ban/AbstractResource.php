<?php

namespace AWSFail2Ban;

abstract class AbstractResource {

    /*
     * For description purposes
     *
     * @var
     */
    static $name;

    /**
     * @var
     */
    static $change_token;

    /*
     * The AWS resource ID of what we are targeting
     *
     * @var
     */
    static $aws_resource_id;

    /*
     * The AWS region (optional)
     *
     * @var
     */
    static $aws_region;

    /**
     * AbstractResource constructor.
     */
    public function __construct() {

        // get CLI options
        $options = getopt('b:u:lfi:n:r:');

        // i = resource id to work with
        if(array_key_exists('i', $options)){
            static::$aws_resource_id = $options['i'];
        }else{
            echo 'You must set a target AWS Resource ID for ' . static::class . PHP_EOL;
            exit(1);
        }

        // i = resource id to work with
        if(array_key_exists('n', $options)){
            static::$name = $options['n'];
        }elseif( static::class === WAFv2::class ){
            echo 'You must set a target IP Set name for ' . static::class . PHP_EOL;
            exit(1);
        }

        // r = aws region to work with
        if(array_key_exists('r', $options)){
            static::$aws_region = $options['r'];
        }

        // b = IP to ban
        if(array_key_exists('b', $options)){
            static::ban($options['b']);
        }

        // u = IP to unban
        if(array_key_exists('u', $options)){
            static::unban($options['u']);
        }

        // l = list banned IPs
        if(array_key_exists('l', $options)){
            static::banlist($options['l']);
        }

        // f = flush banned IPs
        if(array_key_exists('f', $options)){
            static::unbanAll();
        }

    }

    /**
     * Implement this function to filter commands by $aws_resource_id
     *
     * @param $cmd
     * @return mixed
     */
    abstract protected static function cmdFilter($cmd);

    /**
     * Append general AWS CLI command options (e.g. region).
     *
     * Will either return appended to supplied command or
     * as a string with just the options to be added.
     *
     * @param string $cmd
     * @return string
     */
     protected static function cmdOptions($cmd){
        if( isset(static::$aws_region)) {
            return trim($cmd) . ' --region ' . static::$aws_region;
        }else{
            return $cmd;
        }
    }

    /**
     * @return mixed
     */
    abstract public static function getAllIpsBanned($ip_only = false);

    public static function banlist(){

        $allIps = static::getAllIpsBanned(true);
        $allIpsCount = count($allIps);

        echo $allIpsCount . ' banned.' . PHP_EOL;

        foreach($allIps as $ip){
            echo $ip . PHP_EOL;
        }

        exit(0);

    }

    /**
     * @return mixed
     */
    abstract public static function unbanAll();

    /**
     * @param $ip
     * @return mixed
     */
    abstract public static function unban($ip);

    /**
     * @param $ip
     * @return array
     */
    protected static function formatIp($ip, $ip_only = false) {

        // if already formatted, return
        if(is_array($ip) && isset($ip['address'])){
            return $ip;
        }

        // remove cidr notation if specified
        $ip_address = preg_replace('/\/[0-9]*$/', '', $ip);

        // validate IPV4
        if(filter_var($ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){

            if($ip_only === true){
                return $ip_address . '/32';
            }else{
                return [
                    'type' => 'IPV4',
                    'address_cidr' => $ip_address . '/32',
                ];
            }

        // validate IPV6
        }elseif(filter_var($ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){

            if($ip_only === true){
                return $ip_address . '/64';
            }else{
                return [
                    'type' => 'IPV6',
                    'address_cidr' => $ip_address . '/64',
                ];
            }

        }else{
            return null;
        }

    }

    /**
     * @param $ip
     * @return mixed
     */
    abstract public static function ban($ip);

}
