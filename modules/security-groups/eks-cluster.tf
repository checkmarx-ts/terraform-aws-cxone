resource "aws_security_group" "eks_cluster" {
  name        = "eks-cluster-${var.deployment_id}-sg"
  description = "EKS Cluster security group for Checkmarx One deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}

resource "aws_security_group_rule" "node_ingress_cluster_api" {
  description              = "Node groups to Cluster API"
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_node.id
  security_group_id        = aws_security_group.eks_cluster.id
}
