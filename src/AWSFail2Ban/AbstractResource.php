<?php

namespace AWSFail2Ban;

abstract class AbstractResource {

    /*
     * For description purposes
     *
     * @var
     */
    static $name;

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

        //get CLI options
        $options = getopt('b:u:lfi:r:');

        //i = resource id to work with
        if(array_key_exists('i', $options)){
            static::$aws_resource_id = $options['i'];
        }else{
            echo "You must set a target AWS Resource ID for ".self::$name."\n";
            exit(1);
        }

        //r = aws region to work with
        if(array_key_exists('r', $options)){
            static::$aws_region = $options['r'];
        }

        //b = IP to ban
        if(array_key_exists('b', $options)){
            static::ban($options['b']);
        }

        //u = IP to unban
        if(array_key_exists('u', $options)){
            static::unban($options['u']);
        }

        //l = list banned IPs
        if(array_key_exists('l', $options)){
            static::banlist($options['l']);
        }

        //f = flush banned IPs
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
     protected static function cmdOptions($cmd=''){

        if(!empty($cmd)){
            $cmd = trim($cmd).' ';
        }

        if(isset(self::$aws_region)){
            $cmd .= '--region '.self::$aws_region;
        }

        return $cmd;
    }

    /**
     * @return mixed
     */
    abstract public static function getAllIpsBanned();

    public static function banlist(){

        $allIps = static::getAllIpsBanned();
        $allIpsCount = count($allIps);
        echo "$allIpsCount banned.\n";
        foreach($allIps as $ip){
            echo "$ip\n";
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
    protected static function formatIp($ip) {

        if(is_array($ip) && isset($ip['cidr'])){
            return $ip;
        }

        //ip flags
        $ip_type = false;
        $ip_cidr = explode('/', trim($ip));

        //validate IPV4
        if(filter_var($ip_cidr[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
            $ip_type = 'IPV4';
            $ip_cidr = $ip_cidr[0].'/32';
        //validate IPV6
        }elseif(filter_var($ip_cidr[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
            $ip_type = 'IPV6';
            $ip_cidr = $ip_cidr[0].'/64';
        }

        return array(
            'type' => $ip_type,
            'cidr' => $ip_cidr,
        );
    }

    /**
     * @param $ip
     * @return mixed
     */
    abstract public static function ban($ip);

}
