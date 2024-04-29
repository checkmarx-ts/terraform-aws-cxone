
locals {
  sca_scanning_rules = var.include_sca_rules == false ? "" : <<EOF
# These rules are used in SCA scaning, and will vary wildly based on what language/package manager/package repositories are used by the application being scanned with SCA         
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"github.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420065; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"repo.maven.apache.org"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420066; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"registry.npmjs.org"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420067; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"lscr.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420068; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"index.docker.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420069; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"toolbox-data.anchore.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420070; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"registry.hub.docker.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420071; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"hub.docker.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420072; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"ghcr.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420073; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"proxy.golang.org"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420074; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"sum.golang.org"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420075; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"pkg-containers.githubusercontent.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420076; rev:1;)

EOF

  default_suricata_rules = <<EOF
# Amazon Services - these must be allowed, or can be replaced by private VPC Endpoints (which have a charge https://aws.amazon.com/privatelink/pricing/)
# Note that these are AWS Region Dependent
# Reference https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html, https://eksctl.io/usage/eks-private-cluster/
# These rules do not imply support for completely private clusters, but do help with private cluster deployments. 
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"ssm.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190000; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"ec2.${data.aws_region.current.name}.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190001; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"eks.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190002; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"api.ecr.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190003; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"dkr.ecr.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190004; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"ssmmessages.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190005; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"ec2messages.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190006; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"sts.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190007; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"logs.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190008; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"route53.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190009; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"cloudformation.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190010; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"elasticloadbalancing.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190011; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"autoscaling.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24190012; rev:1;)


# Karpenter
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"iam.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24250001; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"api.pricing.us-east-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24250002; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"sqs.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24240001; rev:1;)


# Installation media for kube-system services pods like coredns, aws-node, ebs-csi-controller, ebs-csi-node, kube-proxy
#  The *.dkr.ecr.*.amazonaws.com URLs are typically metadata repos that redirect to prod-$REGION-starport-layer-bucket.s3.$REGION.amazonaws.com to download packages
# References:
#   1. https://docs.aws.amazon.com/eks/latest/userguide/add-ons-images.html
#   2. https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html#ecr-setting-up-s3-gateway
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"877085696533.dkr.ecr.af-south-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420000; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"800184023465.dkr.ecr.ap-east-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420001; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ap-northeast-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420002; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ap-northeast-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420003; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ap-northeast-3.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420004; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ap-south-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420005; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"900889452093.dkr.ecr.ap-south-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420006; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ap-southeast-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420007; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ap-southeast-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420008; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"296578399912.dkr.ecr.ap-southeast-3.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420009; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"491585149902.dkr.ecr.ap-southeast-4.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420010; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.ca-central-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420011; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"761377655185.dkr.ecr.ca-west-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420012; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.eu-central-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420013; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"900612956339.dkr.ecr.eu-central-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420014; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.eu-north-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420015; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"590381155156.dkr.ecr.eu-south-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420016; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"455263428931.dkr.ecr.eu-south-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420017; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.eu-west-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420018; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.eu-west-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420019; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.eu-west-3.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420020; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"066635153087.dkr.ecr.il-central-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420021; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"558608220178.dkr.ecr.me-south-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420022; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"759879836304.dkr.ecr.me-central-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420023; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.sa-east-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420024; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.us-east-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420025; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.us-east-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420026; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"151742754352.dkr.ecr.us-gov-east-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420027; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"01004608.dkr.ecr.us-gov-west-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420028; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.us-west-1.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420029; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"602401143452.dkr.ecr.us-west-2.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420030; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"prod-${data.aws_region.current.name}-starport-layer-bucket.s3.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420031; rev:1;)


# Amazon Linux 2 managed node group updates - region dependent
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"amazonlinux-2-repos-${data.aws_region.current.name}.s3.dualstack.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420032; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"al2023-repos-${data.aws_region.current.name}-de612dc2.s3.dualstack.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420033; rev:1;)


# AWS Load Balancer Controller & Karpenter - public.ecr.aws (metadata) redirects to cloudfront (download)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"public.ecr.aws"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420034; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"d5l0dvt14r5h8.cloudfront.net"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420035; rev:1;)


# Cluster Autoscaler - k8s.gcr.io (metadata) redirects to storage.googleapis.com (download)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"k8s.gcr.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420036; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"storage.googleapis.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420037; rev:1;)


# Kotsadm tools (minio, rqlite) come from docker.io and docker.com
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"registry-1.docker.io"; nocase; startswith; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420038; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"auth.docker.io"; nocase; startswith; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420039; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"production.cloudflare.docker.com"; nocase; startswith; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420040; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"subnet.min.io"; nocase; startswith; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:24250010; rev:1;)


# Replicated APIs - used for license checking
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"replicated.app"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420041; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"proxy.replicated.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420042; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"proxy-auth.replicated.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420043; rev:1;)


# Used by cxone images, and kube-rbac-proxy in CxOne operator
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"gcr.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240419044; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"checkmarx.jfrog.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420044; rev:1;)


# Liquibase schema files required for database migration execution
pass http $HOME_NET any -> $EXTERNAL_NET 80 (http.host; content:"www.liquibase.org"; startswith; endswith; msg:"Match liquidbase.com allowed"; flow:to_server, established; sid:240420062; rev:1;)


# Feature Flags via Split.io
# Reference https://help.split.io/hc/en-us/articles/360006954331-How-do-I-allow-Split-to-work-in-my-environment
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"sdk.split.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420045; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"auth.split.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420046; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"telemetry.split.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420047; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"events.split.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420048; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"streaming.split.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420049; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"cdn.split.io"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420050; rev:1;)
# Fastly (a CDN), which is used for sdk.split.io https://api.fastly.com/public-ip-list. These are used sometimes w/o host name, so SNI cannot be used to filter.
pass tls $HOME_NET any -> [23.235.32.0/20,43.249.72.0/22,103.244.50.0/24,103.245.222.0/23,103.245.224.0/24,104.156.80.0/20,140.248.64.0/18,140.248.128.0/17,146.75.0.0/17,151.101.0.0/16,157.52.64.0/18,167.82.0.0/17,167.82.128.0/20,167.82.160.0/20,167.82.224.0/20,172.111.64.0/18,185.31.16.0/22,199.27.72.0/21,199.232.0.0/16] 443 (msg:"Fastly CDN"; flow:to_server, established; sid:240420051; rev:1;)


# Allow access to s3 buckets for Checkmarx One. Buckets are typically created with a prefix of the deployment id which allows for regex matching
# Example bucket name and suffix: scan-results-bos-ap-southeast-1-lab-19205
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; pcre:"/^${var.deployment_id}.*?\.s3\.dualstack\.${data.aws_region.current.name}\.amazonaws\.com$/i" msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420052; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; pcre:"/^${var.deployment_id}.*?\.s3\.${data.aws_region.current.name}\.amazonaws\.com$/i" msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420053; rev:1;)


# Checkmarx One Scans will upload source to scan-results bucket with url path patterns like "https://s3.${data.aws_region.current.name}.amazonaws.com/scan-results-0aa15147e5f3/source-code/....." 
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"s3.dualstack.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420054; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"s3.${data.aws_region.current.name}.amazonaws.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420055; rev:1;)


# These are the checkmarx services for SCA scanning, cloud IAM (for Authentication to SCA), and codebashing
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"iam.checkmarx.net"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420056; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"api-sca.checkmarx.net"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420057; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"eu.iam.checkmarx.net"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420058; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"eu.api-sca.checkmarx.net"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420059; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"uploads.sca.checkmarx.net"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240420060; rev:1;)
# Scan results buckets are used for SCA scan result syncing, and vary by the connected SCA region (e.g. NA, or EU)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"microservice-scanresults-prod-storage-1an26shc41yi3.s3.amazonaws.com"; startswith; nocase; endswith; msg:"SCA NA region result sync bucket"; flow:to_server, established; sid:240420061; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"api.stagecodebashing.com"; startswith; nocase; endswith; msg:"SCA NA region result sync bucket"; flow:to_server, established; sid:240422001; rev:1;)
# upcoming features                                             
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"cx-sca-containers.es.us-east-1.aws.found.io"; startswith; nocase; endswith; msg:"SCA NA region result sync bucket"; flow:to_server, established; sid:204290001; rev:1;)


# These URLs are randomly generated, and used to discover the correct s3 API signature version to use when communicating with S3 buckets.
# They take two forms, where the long alphanumeric string is randomly generated. The buckets do not exist, but allow minio client
# to attempt to connect to S3 to discover the s3 signature version to use in subsequent requests to the actual buckets
#   1. probe-bucket-sign-vie4gezw1j6w.s3.dualstack.${data.aws_region.current.name}.amazonaws.com
#   2. probe-bsign-jmcvig40f29rwikvncljjtvohv4i4h.s3.dualstack.${data.aws_region.current.name}.amazonaws.com
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; pcre:"/^probe-bucket-sign-[A-z0-9]{12}\.s3\.dualstack\.${data.aws_region.current.name}\.amazonaws\.com$/i"; flow: to_server; msg:"Minio client s3 signature version determination"; sid:240420063;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; pcre:"/^probe-bsign-[A-z0-9]{30}\.s3\.dualstack\.${data.aws_region.current.name}\.amazonaws\.com$/i"; flow: to_server; msg:"Minio client s3 signature version determination"; sid:240420064;)

${local.sca_scanning_rules}

${var.additional_suricata_rules}

EOF
}
