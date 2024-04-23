#******************************************************************************
#   Network Firewall
#******************************************************************************

resource "aws_networkfirewall_firewall" "main" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${var.deployment_id}-checkmarxone"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main[0].arn
  vpc_id              = aws_vpc.main.id
  timeouts {
    create = "40m"
    update = "50m"
    delete = "1h"
  }
  subnet_mapping {
    subnet_id = aws_subnet.firewall[0].id
  }
}

resource "aws_networkfirewall_rule_group" "cxone" {
  count    = var.enable_firewall ? 1 : 0
  capacity = 200
  name     = "${var.deployment_id}-cxone"
  type     = "STATEFUL"
  rule_group {
    rules_source {
      rules_string = var.suricata_rules != null ? var.suricata_rules : local.default_suricata_rules
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "main" {
  count = var.enable_firewall ? 1 : 0
  name  = var.deployment_id
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = [var.stateful_default_action]
    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }
    stateful_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.cxone[0].arn
    }

    dynamic "stateful_rule_group_reference" {
      for_each = { for idx, rg in var.managed_rule_groups : rg => idx if var.create_managed_rule_groups }
      content {
        priority     = stateful_rule_group_reference.value + 2
        resource_arn = "arn:${data.aws_partition.current.id}:network-firewall:${data.aws_region.current.name}:aws-managed:stateful-rulegroup/${stateful_rule_group_reference.key}"
      }
    }

    policy_variables {
      rule_variables {
        key = "HOME_NET"
        ip_set { definition = [var.primary_cidr_block, var.secondary_cidr_block] }
      }
    }
  }
}


# Reference the policy document length of 5120 characters described at https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AWS-logs-and-resource-policy.html#AWS-logs-infrastructure-CWL
# and explains the solution of using /aws/vendedlogs prefix in log group names.
resource "aws_cloudwatch_log_group" "aws_nfw_alert" {
  count             = var.enable_firewall ? 1 : 0
  name              = "/aws/vendedlogs/${var.deployment_id}-aws-nfw-alert"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "aws_nfw_flow" {
  count             = var.enable_firewall ? 1 : 0
  name              = "/aws/vendedlogs/${var.deployment_id}-aws-nfw-flow"
  retention_in_days = 14
}


resource "aws_networkfirewall_logging_configuration" "main" {
  count        = var.enable_firewall ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.main[0].arn
  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.aws_nfw_alert[0].name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.aws_nfw_flow[0].name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}
