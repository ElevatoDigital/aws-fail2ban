<?php

namespace AWSFail2Ban;

require_once 'AbstractResource.php';

class WAF extends AbstractResource {

    static $name = 'WAF';

    /**
     * Appends --ip-set-id to filter commands
     *
     * @param $cmd
     * @return mixed|string
     */
    protected static function cmdFilter($cmd){

        //ensure consistent spacing
        if(!empty($cmd)){
            $cmd = trim($cmd).' ';
        }

        $cmd .= '--ip-set-id '.self::$aws_resource_id;

        return $cmd;
    }

    /**
     * Get all IPs that are banned from the IPSet
     *
     * @return array|mixed
     * @throws \Exception
     */
    public static function getAllIpsBanned($returnIpType=false) {

        $banned = array();

        //build cmd to get security group info
        $cmd = 'aws waf-regional get-ip-set';

        //filter by --ip-set-id
        $cmd = self::cmdFilter($cmd);

        //add region
        $cmd = self::cmdOptions($cmd);

        $response_json = shell_exec($cmd);

        $response = json_decode($response_json, 1);

        if(!isset($response['IPSet'])){
            throw new \Exception("IPSet not returned in response");
        }

        if(empty($response['IPSet'])){
            echo "No IPSet found for ".self::$aws_resource_id.". Are you in the right region?\n";
            exit(1);
        }

        //added verification
        if($response['IPSet']['IPSetId'] != self::$aws_resource_id){
            exit(1);
        }

        if($returnIpType === false){

            //cycle through rules
            foreach($response['IPSet']['IPSetDescriptors'] as $entry) {
                $banned[] = $entry['Value'];
            }

            return $banned;

        }else{

            return $response['IPSet']['IPSetDescriptors'];

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

        //format ip
        $ip = self::formatIp($ip);

        $bannedList = self::getAllIpsBanned();

        if(in_array($ip['cidr'],$bannedList)){
            return true;
        }else{
            return false;
        }
    }

    public static function unbanAll(){

        $allIps = static::getAllIpsBanned(true);
        $allIpsCount = count($allIps);

        //due to the possibility of the change-token expiring before
        //we can unban all ips, we will verify if the ip was actually
        //unbanned and repeat if necessary until this script times
        //out
        while($allIpsCount>0) {

            try {

                $allPosition = 0;
                $iterationMax = 1000;
                $iterationLoop = -1;

                while ($allPosition < $allIpsCount) {

                    $iterationLoop++;
                    $iterationPosition = 0;
                    $iterationIPSetDescriptors = array();

                    //echo "$allPosition\n";

                    while ($iterationPosition < $iterationMax) {

                        //echo "$iterationPosition\n";

                        if (!isset($allIps[$allPosition])) {

                            $iterationPosition++;
                            $allPosition++;
                            continue;

                        } else {

                            $iterationIPSetDescriptors[] = 'Action=DELETE,IPSetDescriptor=\'{Type='.$allIps[$allPosition]['Type'].',Value='.$allIps[$allPosition]['Value'].'}\'';

                            $iterationPosition++;
                            $allPosition++;

                        }
                    }

                    //each change requires a change token
                    $change_token = static::getChangeToken();

                    $cmd = "aws waf-regional update-ip-set --change-token $change_token --updates ".implode(" ", $iterationIPSetDescriptors);

                    //filters by ip-set-it
                    $cmd = self::cmdFilter($cmd);

                    //adds region and other options
                    $cmd = self::cmdOptions($cmd);

                    //execute api call
                    echo "Unbanning ".($iterationMax*$iterationLoop)." to ".($iterationMax*$iterationLoop+$iterationPosition)." of $allIpsCount banned IPs\n";

                    shell_exec($cmd);

                }

            } catch (\Exception $e) {

                echo $e->getMessage() . "\n";

            }

            $allIps = static::getAllIpsBanned();
            $allIpsCount = count($allIps);

        }

    }

    /**
     * @return mixed
     */
    public static function getChangeToken(){

        //aws cmd to add IP
        $cmd = 'aws waf-regional get-change-token';

        //adds region and other options
        $cmd = self::cmdOptions($cmd);

        //execute
        $response_json = shell_exec($cmd);

        //convert to json
        $response = json_decode($response_json, 1);

        //no change token
        if(!isset($response['ChangeToken'])){
            echo "unable to get ChangeToken\n";
        }

        //return change-token
        echo "change-token=${response['ChangeToken']}\n";
        return $response['ChangeToken'];
    }

    /**
     * Unban an IP by removing it from the IPSet
     *
     * @param $ip
     * @return mixed|void
     */
    public static function unban($ip) {

        $banned=true;

        //due to the possibility of the change-token expiring before
        //we can unban the ip, we will verify if the ip was actually
        //unbanned and repeat if necessary until this script times
        //out
        while($banned==true){

            try{

                //each change requires a change token
                $change_token = static::getChangeToken();

                //make sure IP is formatted for AWS API
                $ip = self::formatIp($ip);

                //aws cmd to add IP
                $cmd = "aws waf-regional update-ip-set --change-token $change_token --updates 'Action=DELETE,IPSetDescriptor={Type=${ip['type']},Value=${ip['cidr']}}'";

                //filters by ip-set-it
                $cmd = self::cmdFilter($cmd);

                //adds region and other options
                $cmd = self::cmdOptions($cmd);

                //execute api call
                echo "Unbanning ${ip['cidr']}\n";
                shell_exec($cmd);

                //success
                $banned = self::checkIfBanned($ip);

            }catch (\Exception $e){

                echo $e->getMessage()."\n";

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

        //each change requires a change token
        $change_token = static::getChangeToken();

        //make sure IP is formatted for AWS API
        $ip = self::formatIp($ip);

        //aws cmd to add IP
        $cmd = "aws waf-regional update-ip-set --change-token $change_token --updates 'Action=INSERT,IPSetDescriptor={Type=${ip['type']},Value=${ip['cidr']}}'";

        //filters by ip-set-it
        $cmd = self::cmdFilter($cmd);

        //adds region and other options
        $cmd = self::cmdOptions($cmd);

        //execute api call
        echo "Banning ${ip['cidr']}\n";
        shell_exec($cmd);

    }

}
