

# VPC Size
The provided `vpc_cidr` is expected to be a /16 network. This module will divide the provided block into 3 subnets per availability zone.

Subnet Type | CIDR | # of Hosts
---|---|---
Private | /18 | 16,256
Public | /21 | 2,032
Database | /22 | 1,016