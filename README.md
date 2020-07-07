Credits: Originally forked from https://github.com/anthonymartin/aws-acl-fail2ban

# aws-fail2ban
This package adds capability to fail2ban for managing IPSets on AWS (classic waf-regional and new wafv2). An IPSet that is managed via fail2ban can be easily added to a WAF/ACL rule that blocks addresses in that IPSet. This allows for fail2ban integration with AWS Loadbalancers and other resources that can be associated with an AWS WAF to allow banning at the edge of your AWS environment.

Dependencies
------
* An IAM account with an applicable IAM policy and an API Access Key (see the examples folder). 
* AWS CLI must be installed and your access credentials must be setup as specified in AWS CLI docs (either through a ~/.aws/config or through an environment variable). https://docs.aws.amazon.com/cli/latest/userguide/install-cliv1.html
* For waf-regional, you need to have created a regional WAF, an IPSet and recorded the IPSet id.
* For wafv2, you need to have a regional WAFv2 ACL, an IPSet and recorded the IPSet id and name.
* For either waf option, you should an ACL rule that blocks IP addresses created in the IPSet that you configured.
* If you haven't configured Nginx/Apache to use X-Forwarded-For, you will need to do that first so that you are capturing the real client IP address and not the loadbalancer's IP address.

AWS Docs - https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html
NGINX Access Logs - https://ma.ttias.be/nginx-access-log-log-the-real-users-ip-instead-of-the-proxy/
NGINX Proxy - https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
Apache Access Logs - https://aws.amazon.com/premiumsupport/knowledge-center/log-client-ip-load-balancer-apache/
Cloudflare - https://support.cloudflare.com/hc/en-us/articles/200170706-How-do-I-restore-original-visitor-IP-with-Nginx-

Installation
-----
1. The recommended method of installation is by using composer to install: `composer require deltasystems/aws-fail2ban` - alternatively, you can clone or download this repository.
2. Ensure that your apache configuration and your fail2ban configuration is correct. Some help has been provided below.

fail2ban Configuration
-----
1. Copy `fail2ban/action.d/aws-acl.conf` in `/etc/fail2ban/action.d/` directory. Modify with IPSet information recorded above.
2. (Optional) Create a filter to match whatever log file you are trying to log.
3. Create or update your jail configuration. See examples in code.
  
