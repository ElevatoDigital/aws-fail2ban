Credits: Originally forked from https://github.com/anthonymartin/aws-acl-fail2ban

# aws-fail2ban
This package includes a script and fail2ban configuration that allows you to interact with applicable AWS resources via fail2ban actions. For example, you can add an IP to a WAF Regional IPSet that is used to deny access to resources. This makes it possible to continue using fail2ban on your servers behind an Amazon loadbalancer and ban ips upstream from that server.

Dependencies
------
* An IAM account with an applicable IAM policy and an API Access Key (see the examples folder). 
* AWS CLI must be installed and your access credentials must be setup as specified in AWS CLI docs (either through a ~/.aws/config or through an environment variable). Example:
```
#CentOS
yum install 

#Ubuntu
apt-get install awscli

#system agnostic
aws configure
```
* For a WAF, you need to have created an IPSet and recorded the ARN.
* If you haven't configured Nginx/Apache to use X-Forwarded-For, you will need to do that first.

AWS Docs - https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html
NGINX Access Logs - https://ma.ttias.be/nginx-access-log-log-the-real-users-ip-instead-of-the-proxy/
NGINX Proxy - https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
Apache Access Logs - https://aws.amazon.com/premiumsupport/knowledge-center/log-client-ip-load-balancer-apache/
Cloudflare - https://support.cloudflare.com/hc/en-us/articles/200170706-How-do-I-restore-original-visitor-IP-with-Nginx-

Installation
-----
1. The recommended method of installation is by using composer to install: `composer require anthonymartin/aws_acl_fail2ban` - alternatively, you can clone or download this repository.
2. Ensure that your apache configuration and your fail2ban configuration is correct. Some help has been provided below.

Apache Configuration
------
1. Enable RemoteIP mod
2. Update apache configuration - the configuration below is what my configuration found at /etc/apache2/apache2.conf looks like. Be sure to include RemoteIPHeader and replace LogFormat with the lines found below.
  
  ```
    RemoteIPHeader X-Forwarded-For
    LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
    LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %O" common
    LogFormat "%{Referer}i -> %U" referer
    LogFormat "%{User-agent}i" agent
  ```

3. run `sudo service apache2 reload`
 

fail2ban Configuration
-----
1. Copy `fail2ban/action.d/aws-acl.conf` in `/etc/fail2ban/action.d/` directory
2. Copy `fail2ban/filter.d/aws-acl-example-filter.conf` to `/etc/fail2ban/filter.d/` directory
2. Update `actionban` and `actionunban` definitions in `/etc/fail2ban/action.d/aws-acl.conf`. You need tos replace both instances of `/path/to/aws-acl-fail2ban` to the location of `aws-acl-fail2ban` on your server. If you've installed with composer, the location is `vendor/bin/aws-acl-fail2ban`, otherwise the location is in `bin/aws-acl-fail2ban`. You should use the absolute path when updating `actionban` and `actionunban`.
3. Replace both instances of `ACL_ID_GOES_HERE` in `/etc/fail2ban/action.d/aws-acl.conf` with the acl-id of the ACL that you would like to use.
3. Create or update your jail.local configuration. Replace the filter definition below with your own filter if you have one. The example filter configuration included in this package will match all POST and GET requests that are not images, css or javascript (note this doesn't include font files as of this time, but it probably should). The filter together with the jail.local configuration here will be useful for stopping crawl attempts and certain types of HTTP Flood DoS or brute force attacks. Here's an example jail.local configuration:
  
  ```
  [aws-acl-example]
  enabled = true
  filter = aws-acl-example-filter
  action = aws-acl
    sendmail-whois[name=LoginDetect, dest=youremail@example.com, sender=youremail@local.hostname, sendername="Fail2Ban"]
  logpath = /var/log/apache2/access.log
  maxretry = 60
  findtime = 60
  bantime = 14400
  ```
  
