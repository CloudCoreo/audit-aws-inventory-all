# ACM
# APIGateway
# AppStream
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
# Batch
# Budgets
# CloudDirectory
# CloudFormation
# CloudFront
# CloudHSM
# CloudSearch
# CloudSearchDomain
# CloudTrail
# CloudWatch
# CloudWatchEvents
# CloudWatchLogs
# CodeBuild
# CodeCommit
# CodeDeploy
# CodePipeline
# CodeStar
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
# CostandUsageReportService
# DataPipeline
# DatabaseMigrationService
# DeviceFarm
# DirectConnect
# DirectoryService
# DynamoDB
# DynamoDBStreams
# EC2
# ECR
# ECS
# EFS
# EMR
# ElastiCache
# ElasticBeanstalk
# ElasticLoadBalancing
# ElasticLoadBalancingV2
# ElasticTranscoder
# ElasticsearchService
# Firehose
# GameLift
# Glacier
# Health
# IAM
# ImportExport
# Inspector
# IoT
# IoTDataPlane
# KMS
# Kinesis
# KinesisAnalytics
# Lambda
# LambdaPreview
# Lex
# LexModelBuildingService
# Lightsail
# MTurk
# MachineLearning
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
# OpsWorksCM
# Organizations
# Pinpoint
# Polly
# RDS
# Redshift
# Rekognition
# ResourceGroupsTaggingAPI
# Route53
#   - get_checker_ip_ranges({})
#     - id: checker_ip_ranges
#   - get_health_check_status({})
#   - list_geo_locations <- SKIPPING due to @engine_bug_exclusions
#   - list_health_checks <- SKIPPING due to @engine_bug_exclusions
#   - list_hosted_zones <- SKIPPING due to @engine_bug_exclusions
#   - list_resource_record_sets({})
#   - list_reusable_delegation_sets <- SKIPPING due to @engine_bug_exclusions
#   - list_traffic_policies({})
#     - id: traffic_policy_summaries.id
#   - list_traffic_policy_instances({})
#     - id: traffic_policy_instances.id
#   - list_traffic_policy_versions({})
#   - list_vpc_association_authorizations({})
# Route53Domains
# S3
# SES
# SMS
# SNS
# SQS
# SSM
# STS
# SWF
# ServiceCatalog
# Shield
# SimpleDB
# Snowball
# States
# StorageGateway
# Support
# WAF
# WAFRegional
# WorkDocs
# WorkSpaces
# XRay
coreo_aws_rule "route53-inventory-checker-ip-ranges" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Checker Ip Ranges Inventory"
  description "This rule performs an inventory on the Route53 service using the get_checker_ip_ranges function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_checker_ip_ranges"]
  audit_objects ["object.checker_ip_ranges"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.checker_ip_ranges"]
  
end
coreo_aws_rule "route53-inventory-traffic-policies" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Traffic Policies Inventory"
  description "This rule performs an inventory on the Route53 service using the list_traffic_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_traffic_policies"]
  audit_objects ["object.traffic_policy_summaries.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.traffic_policy_summaries.id"]
  
end
coreo_aws_rule "route53-inventory-traffic-policy-instances" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Traffic Policy Instances Inventory"
  description "This rule performs an inventory on the Route53 service using the list_traffic_policy_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_traffic_policy_instances"]
  audit_objects ["object.traffic_policy_instances.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.traffic_policy_instances.id"]
  
end
  
coreo_aws_rule_runner "route53-inventory-runner" do
  action :run
  service :Route53
  rules ["route53-inventory-checker-ip-ranges", "route53-inventory-traffic-policies", "route53-inventory-traffic-policy-instances"]
  regions ['us-east-1']
end
