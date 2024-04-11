# aws-ipset-automation
Quick automation for allow/block listing IPs on AWS WAF using python-whois 

# About
This automation allow Security Operation teams to automaticaly maintain list of IPs that will be blocked or allowed in the AWS WAFv2 platform by performing reverse whois lookups.

This project is based on AWS's [update-aws-ip-ranges](https://github.com/aws-samples/update-aws-ip-ranges) but with a few twists: 

* We'll be using reverse whois lookup with custom whois servers, which may help when the resource must be exposed to an partner ASN or in MTLS scenarios 

* We'll be using time based events for constantly check for new IP blocks instead of SNS Topics


Our process will look something like:

```
                          +-----------------+         
                          | Lambda          |         
                          | Execution Role  |         
                          +--------+--------+         
                                   |                  
                                   |                  +---------------------+
+--------------------+    +--------+--------+         |                     |
|EventBus Schedule   +--->+ Lambda function +----+--->|AWS WAF IPv4/IPv6 Set|
|cron(0?***)         |    +--------+--------+         |                     |
+--------------------+             |                  +---------------------+
                                   |                 
                                   v             
                          +--------+--------+         
                          | CloudWatch Logs |         
                          +-----------------+
```
