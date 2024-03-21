resource "aws_security_group" "eks_node" {
  name        = "eks-node-${var.deployment_id}-sg"
  description = "EKS Node security group for Checkmarx One deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}

resource "aws_security_group_rule" "node_self_tcp_53" {
  description       = "Node to node CoreDNS"
  type              = "ingress"
  from_port         = 53
  to_port           = 53
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_self_udp_53" {
  description       = "Node to node CoreDNS UDP"
  type              = "ingress"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  self              = true
  security_group_id = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_self_tcp_ephemeral" {
  description       = "Node to node ingress on ephemeral ports"
  type              = "ingress"
  from_port         = 1025
  to_port           = 65535
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.eks_node.id
}

# Well known ports are needed, because some services are on nodes at ports below 1025 e.g. 8080, or 80.
# And without this rule, some interservice communication with CxOne application layer will fail.
resource "aws_security_group_rule" "node_self_tcp_well_known" {
  description       = "Node to node ingress on well known ports"
  type              = "ingress"
  from_port         = 1
  to_port           = 1024
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_cluster_tcp_4443" {
  description              = "Cluster API to node 4443/tcp webhook"
  type                     = "ingress"
  from_port                = 4443
  to_port                  = 4443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_cluster.id
  security_group_id        = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_cluster_tcp_8443" {
  description              = "Cluster API to node 8443/tcp webhook"
  type                     = "ingress"
  from_port                = 8443
  to_port                  = 8443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_cluster.id
  security_group_id        = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_cluster_tcp_443" {
  description              = "Cluster API to node groups"
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_cluster.id
  security_group_id        = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_cluster_tcp_9443" {
  description              = "Cluster API to node 9443/tcp webhook"
  type                     = "ingress"
  from_port                = 9443
  to_port                  = 9443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_cluster.id
  security_group_id        = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_cluster_tcp_6443" {
  description              = "Cluster API to node 6443/tcp webhook"
  type                     = "ingress"
  from_port                = 6443
  to_port                  = 6443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_cluster.id
  security_group_id        = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_cluster_kubelets" {
  description              = "Cluster API to node kubelets"
  type                     = "ingress"
  from_port                = 10250
  to_port                  = 10250
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_cluster.id
  security_group_id        = aws_security_group.eks_node.id
}


resource "aws_security_group_rule" "node_egress_all_internal" {
  description       = "All protocols"
  type              = "egress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = local.internal_vpc_cidrs
  security_group_id = aws_security_group.eks_node.id
}

resource "aws_security_group_rule" "node_ingress_all_internal" {
  description       = "All protocols"
  type              = "ingress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = local.internal_vpc_cidrs
  security_group_id = aws_security_group.eks_node.id
}




