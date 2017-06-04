# ACM
#   - list_certificates
#     - id: certificate_summary_list.certificate_arn
# APIGateway
#   - get_api_keys
#     - id: items.id
#   - get_client_certificates
#     - id: items.client_certificate_id
#   - get_domain_names
#     - id: items.certificate_arn
#   - get_rest_apis
#     - id: items.id
#   - get_sdk_types
#     - id: items.id
#   - get_usage_plans
#     - id: items.id
# AppStream
#   - describe_images
#     - id: images.arn
#   - describe_fleets
#     - id: fleets.arn
#   - describe_stacks
#     - id: stacks.arn
# ApplicationAutoScaling
# ApplicationDiscoveryService
# AutoScaling
#   - describe_scaling_activities
#     - id: activities.activity_id
#   - describe_account_limits
#     - id: NA
#   - describe_adjustment_types
#     - id: adjustment_types.adjustment_type
#   - describe_auto_scaling_groups
#     - id: auto_scaling_groups.auto_scaling_group_arn
#   - describe_auto_scaling_instances
#     - id: auto_scaling_instances.instance_id
#   - describe_auto_scaling_notification_types
#     - id: auto_scaling_notification_types
#   - describe_launch_configurations
#     - id: launch_configurations.launch_configuration_arn
#   - describe_lifecycle_hook_types
#     - id: lifecycle_hook_types
#   - describe_metric_collection_types
#     - id: metrics.metric
#   - describe_notification_configurations
#     - id: notification_configurations.topic_arn
#   - describe_policies
#     - id: scaling_policies.policy_arn
#   - describe_scaling_process_types
#     - id: processes.process_name
#   - describe_scheduled_actions
#     - id: scheduled_update_group_actions.scheduled_action_arn
#   - describe_termination_policy_types
#     - id: termination_policy_types
# Batch
#   - describe_compute_environments
#     - id: compute_environments.compute_environment_arn
#   - describe_job_definitions
#     - id: job_definitions.job_definition_arn
#   - describe_job_queues
#     - id: job_queues.job_queue_arn
# Budgets
# CloudDirectory
#   - list_development_schema_arns
#     - id: schema_arns
#   - list_directories
#     - id: directories.directory_arn
#   - list_published_schema_arns
#     - id: schema_arns
# CloudFormation
#   - describe_stacks
#     - id: stacks.role_arn
#   - describe_account_limits
#     - id: account_limits.name
#   - list_exports
#     - id: exports.exporting_stack_id
#   - list_stacks
#     - id: stack_summaries.stack_id
# CloudFront
#   - list_cloud_front_origin_access_identities
#     - id: cloud_front_origin_access_identity_list.items.id
#   - list_distributions
#     - id: distribution_list.items.arn
#   - list_streaming_distributions
#     - id: streaming_distribution_list.items.arn
# CloudHSM
#   - list_available_zones
#     - id: az_list
#   - list_hapgs
#     - id: hapg_list
#   - list_hsms
#     - id: hsm_list
#   - list_luna_clients
#     - id: client_list
# CloudSearch
#   - describe_domains
#     - id: domain_status_list.arn
#   - list_domain_names
#     - id: NA
# CloudSearchDomain
# CloudTrail
#   - describe_trails
#     - id: trail_list.trail_arn
#   - list_public_keys
#     - id: public_key_list.value
# CloudWatch
#   - describe_alarms
#     - id: metric_alarms.alarm_arn
#   - list_metrics
#     - id: metrics.metric_name
# CloudWatchEvents
#   - list_rules
#     - id: rules.role_arn
# CloudWatchLogs
#   - describe_export_tasks
#     - id: export_tasks.task_id
#   - describe_destinations
#     - id: destinations.role_arn
#   - describe_log_groups
#     - id: log_groups.arn
#   - describe_metric_filters
#     - id: metric_filters.filter_name
# CodeBuild
#   - list_builds
#     - id: ids
#   - list_curated_environment_images
#     - id: platforms.platform
#   - list_projects
#     - id: projects
# CodeCommit
#   - list_repositories
#     - id: repositories.repository_id
# CodeDeploy
#   - list_applications
#     - id: applications
#   - list_deployment_configs
#     - id: deployment_configs_list
#   - list_deployments
#     - id: deployments
#   - list_on_premises_instances
#     - id: instance_names
# CodePipeline
#   - list_action_types
#     - id: action_types.id.owner
#   - list_pipelines
#     - id: pipelines.name
# CodeStar
#   - list_projects
#     - id: projects.project_arn
#   - list_user_profiles
#     - id: user_profiles.user_arn
# CognitoIdentity
# CognitoIdentityProvider
# CognitoSync
# ConfigService
#   - describe_config_rule_evaluation_status
#     - id: config_rules_evaluation_status.config_rule_arn
#   - describe_config_rules
#     - id: config_rules.config_rule_arn
#   - describe_configuration_recorder_status
#     - id: configuration_recorders_status.last_status_change_time
#   - describe_configuration_recorders
#     - id: configuration_recorders.role_arn
#   - describe_delivery_channel_status
#     - id: delivery_channels_status.name
#   - describe_delivery_channels
#     - id: delivery_channels.sns_topic_arn
# CostandUsageReportService
# DataPipeline
#   - list_pipelines
#     - id: pipeline_id_list.id
# DatabaseMigrationService
#   - describe_account_attributes
#     - id: account_quotas.account_quota_name
#   - describe_certificates
#     - id: certificates.certificate_arn
#   - describe_connections
#     - id: connections.endpoint_arn
#   - describe_endpoint_types
#     - id: supported_endpoint_types.engine_name
#   - describe_endpoints
#     - id: endpoints.endpoint_arn
#   - describe_orderable_replication_instances
#     - id: orderable_replication_instances.min_allocated_storage
#   - describe_replication_instances
#     - id: replication_instances.replication_instance_arn
#   - describe_replication_subnet_groups
#     - id: replication_subnet_groups.vpc_id
#   - describe_replication_tasks
#     - id: replication_tasks.source_endpoint_arn
# DeviceFarm
# DirectConnect
#   - describe_connections
#     - id: connections.lag_id
#   - describe_lags
#     - id: lags.lag_id
#   - describe_locations
#     - id: locations.location_name
#   - describe_virtual_gateways
#     - id: virtual_gateways.virtual_gateway_id
#   - describe_virtual_interfaces
#     - id: virtual_interfaces.virtual_interface_id
# DirectoryService
#   - describe_snapshots
#     - id: snapshots.snapshot_id
#   - describe_directories
#     - id: directory_descriptions.directory_id
#   - describe_event_topics
#     - id: event_topics.topic_arn
#   - describe_trusts
#     - id: trusts.trust_id
#   - get_directory_limits
#     - id: NA
# DynamoDB
#   - describe_limits
#     - id: NA
#   - list_tables
#     - id: last_evaluated_table_name
# DynamoDBStreams
#   - list_streams
#     - id: last_evaluated_stream_arn
# EC2
#   - describe_account_attributes
#     - id: account_attributes.attribute_name
#   - describe_addresses
#     - id: addresses.allocation_id
#   - describe_availability_zones
#     - id: availability_zones.region_name
#   - describe_bundle_tasks
#     - id: bundle_tasks.bundle_id
#   - describe_classic_link_instances
#     - id: instances.instance_id
#   - describe_conversion_tasks
#     - id: conversion_tasks.import_volume.volume.id
#   - describe_customer_gateways
#     - id: customer_gateways.customer_gateway_id
#   - describe_dhcp_options
#     - id: dhcp_options.dhcp_options_id
#   - describe_egress_only_internet_gateways
#     - id: egress_only_internet_gateways.egress_only_internet_gateway_id
#   - describe_export_tasks
#     - id: export_tasks.export_task_id
#   - describe_flow_logs
#     - id: flow_logs.deliver_logs_permission_arn
#   - describe_host_reservations
#     - id: host_reservation_set.offering_id
#   - describe_hosts
#     - id: hosts.host_id
#   - describe_iam_instance_profile_associations
#     - id: iam_instance_profile_associations.iam_instance_profile.arn
#   - describe_images
#     - id: images.image_id
#   - describe_import_image_tasks
#     - id: import_image_tasks.import_task_id
#   - describe_import_snapshot_tasks
#     - id: import_snapshot_tasks.import_task_id
#   - describe_instance_status
#     - id: instance_statuses.instance_id
#   - describe_instances
#     - id: reservations.instances.iam_instance_profile.arn
#   - describe_internet_gateways
#     - id: internet_gateways.internet_gateway_id
#   - describe_key_pairs
#     - id: key_pairs.key_name
#   - describe_moving_addresses
#     - id: moving_address_statuses.public_ip
#   - describe_nat_gateways
#     - id: nat_gateways.subnet_id
#   - describe_network_acls
#     - id: network_acls.vpc_id
#   - describe_network_interfaces
#     - id: network_interfaces.subnet_id
#   - describe_placement_groups
#     - id: placement_groups.group_name
#   - describe_prefix_lists
#     - id: prefix_lists.prefix_list_id
#   - describe_reserved_instances
#     - id: reserved_instances.reserved_instances_id
#   - describe_reserved_instances_modifications
#     - id: reserved_instances_modifications.reserved_instances_modification_id
#   - describe_reserved_instances_offerings
#     - id: reserved_instances_offerings.reserved_instances_offering_id
#   - describe_route_tables
#     - id: route_tables.route_table_id
#   - describe_scheduled_instances
#     - id: scheduled_instance_set.scheduled_instance_id
#   - describe_security_groups
#     - id: security_groups.group_id
#   - describe_snapshots
#     - id: snapshots.data_encryption_key_id
#   - describe_spot_fleet_requests
#     - id: spot_fleet_request_configs.spot_fleet_request_config.launch_specifications.iam_instance_profile.arn
#   - describe_spot_instance_requests
#     - id: spot_instance_requests.launch_specification.iam_instance_profile.arn
#   - describe_subnets
#     - id: subnets.vpc_id
#   - describe_volume_status
#     - id: volume_statuses.volume_id
#   - describe_volumes
#     - id: volumes.volume_id
#   - describe_volumes_modifications
#     - id: volumes_modifications.volume_id
#   - describe_vpc_endpoint_services
#     - id: service_names
#   - describe_vpc_endpoints
#     - id: vpc_endpoints.vpc_id
#   - describe_vpc_peering_connections
#     - id: vpc_peering_connections.vpc_peering_connection_id
#   - describe_vpcs
#     - id: vpcs.vpc_id
#   - describe_vpn_connections
#     - id: vpn_connections.vpn_gateway_id
#   - describe_vpn_gateways
#     - id: vpn_gateways.vpn_gateway_id
#   - describe_regions
#     - id: regions.region_name
# ECR
#   - describe_repositories
#     - id: repositories.repository_arn
# ECS
#   - describe_clusters
#     - id: failures.arn
#   - list_clusters
#     - id: cluster_arns
#   - list_task_definition_families
#     - id: families
#   - list_task_definitions
#     - id: task_definition_arns
# EFS
#   - describe_file_systems
#     - id: file_systems.file_system_id
# EMR
#   - list_clusters
#     - id: clusters.id
#   - list_security_configurations
#     - id: security_configurations.name
# ElastiCache
#   - describe_snapshots
#     - id: snapshots.topic_arn
#   - describe_cache_clusters
#     - id: cache_clusters.notification_configuration.topic_arn
#   - describe_cache_engine_versions
#     - id: cache_engine_versions.engine
#   - describe_cache_parameter_groups
#     - id: cache_parameter_groups.cache_parameter_group_name
#   - describe_cache_subnet_groups
#     - id: cache_subnet_groups.vpc_id
#   - describe_events
#     - id: events.source_identifier
#   - describe_replication_groups
#     - id: replication_groups.replication_group_id
#   - describe_reserved_cache_nodes
#     - id: reserved_cache_nodes.reserved_cache_node_id
#   - describe_reserved_cache_nodes_offerings
#     - id: reserved_cache_nodes_offerings.reserved_cache_nodes_offering_id
# ElasticBeanstalk
#   - describe_events
#     - id: events.platform_arn
#   - describe_application_versions
#     - id: application_versions.build_arn
#   - describe_applications
#     - id: applications.application_name
#   - describe_configuration_options
#     - id: platform_arn
#   - describe_environments
#     - id: environments.platform_arn
#   - list_available_solution_stacks
#     - id: solution_stack_details.solution_stack_name
#   - list_platform_versions
#     - id: platform_summary_list.platform_arn
# ElasticLoadBalancing
#   - describe_load_balancers
#     - id: load_balancer_descriptions.vpc_id
#   - describe_load_balancer_policies
#     - id: policy_descriptions.policy_name
#   - describe_load_balancer_policy_types
#     - id: policy_type_descriptions.policy_type_name
# ElasticLoadBalancingV2
#   - describe_load_balancers
#     - id: load_balancers.load_balancer_arn
#   - describe_ssl_policies
#     - id: ssl_policies.ssl_protocols
#   - describe_target_groups
#     - id: target_groups.target_group_arn
# ElasticTranscoder
#   - list_pipelines
#     - id: pipelines.aws_kms_key_arn
#   - list_presets
#     - id: presets.arn
# ElasticsearchService
#   - list_domain_names
#     - id: domain_names.domain_name
#   - list_elasticsearch_versions
#     - id: elasticsearch_versions
# Firehose
#   - list_delivery_streams
#     - id: delivery_stream_names
# GameLift
#   - list_builds
#     - id: builds.build_id
#   - describe_ec2_instance_limits
#     - id: ec2_instance_limits.ec2_instance_type
#   - describe_fleet_attributes
#     - id: fleet_attributes.fleet_arn
#   - describe_game_session_queues
#     - id: game_session_queues.game_session_queue_arn
#   - list_aliases
#     - id: aliases.alias_arn
#   - list_fleets
#     - id: fleet_ids
# Glacier
#   - list_vaults
#     - id: vault_list.vault_arn
# Health
# IAM
#   - get_account_authorization_details
#     - id: user_detail_list.arn
#   - list_access_keys
#     - id: access_key_metadata.access_key_id
#   - list_account_aliases
#     - id: account_aliases
#   - list_groups
#     - id: groups.arn
#   - list_instance_profiles
#     - id: instance_profiles.arn
#   - list_policies
#     - id: policies.arn
#   - list_mfa_devices
#     - id: mfa_devices.user_name
#   - list_open_id_connect_providers
#     - id: open_id_connect_provider_list.arn
#   - list_saml_providers
#     - id: saml_provider_list.arn
#   - list_ssh_public_keys
#     - id: ssh_public_keys.ssh_public_key_id
#   - list_roles
#     - id: roles.arn
#   - list_signing_certificates
#     - id: certificates.certificate_id
#   - list_server_certificates
#     - id: server_certificate_metadata_list.arn
#   - list_service_specific_credentials
#     - id: service_specific_credentials.service_specific_credential_id
#   - list_virtual_mfa_devices
#     - id: virtual_mfa_devices.user.arn
#   - list_users
#     - id: users.arn
# ImportExport
#   - list_jobs
#     - id: jobs.job_id
# Inspector
#   - list_assessment_runs
#     - id: assessment_run_arns
#   - list_assessment_targets
#     - id: assessment_target_arns
#   - list_assessment_templates
#     - id: assessment_template_arns
#   - list_event_subscriptions
#     - id: subscriptions.topic_arn
#   - list_findings
#     - id: finding_arns
#   - list_rules_packages
#     - id: rules_package_arns
# IoT
#   - list_certificates
#     - id: certificates.certificate_arn
#   - list_policies
#     - id: policies.policy_arn
#   - list_ca_certificates
#     - id: certificates.certificate_arn
#   - list_outgoing_certificates
#     - id: outgoing_certificates.certificate_arn
#   - list_thing_types
#     - id: thing_types.thing_type_name
#   - list_things
#     - id: things.thing_type_name
#   - list_topic_rules
#     - id: rules.rule_arn
# IoTDataPlane
# KMS
#   - list_aliases
#     - id: aliases.alias_arn
#   - list_keys
#     - id: keys.key_arn
# Kinesis
#   - describe_limits
#     - id: NA
#   - list_streams
#     - id: stream_names
# KinesisAnalytics
#   - list_applications
#     - id: application_summaries.application_arn
# Lambda
#   - get_account_settings
#     - id: NA
#   - list_event_source_mappings
#     - id: event_source_mappings.function_arn
#   - list_functions
#     - id: functions.function_arn
# LambdaPreview
#   - list_functions
#     - id: functions.function_arn
#   - list_event_sources
#     - id: event_sources.function_name
# Lex
# LexModelBuildingService
#   - get_bots
#     - id: bots.name
#   - get_builtin_intents
#     - id: intents.signature
#   - get_builtin_slot_types
#     - id: slot_types.signature
#   - get_intents
#     - id: intents.name
#   - get_slot_types
#     - id: slot_types.name
# Lightsail
#   - get_regions
#     - id: regions.display_name
#   - get_active_names
#     - id: active_names
#   - get_blueprints
#     - id: blueprints.blueprint_id
#   - get_bundles
#     - id: bundles.bundle_id
#   - get_domains
#     - id: domains.arn
#   - get_instance_snapshots
#     - id: instance_snapshots.arn
#   - get_instances
#     - id: instances.arn
#   - get_key_pairs
#     - id: key_pairs.arn
#   - get_operations
#     - id: operations.id
#   - get_static_ips
#     - id: static_ips.arn
# MTurk
# MachineLearning
#   - describe_batch_predictions
#     - id: results.ml_model_id
#   - describe_data_sources
#     - id: results.role_arn
#   - describe_evaluations
#     - id: results.ml_model_id
#   - describe_ml_models
#     - id: results.ml_model_id
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
#   - describe_stacks
#     - id: stacks.service_role_arn
#   - describe_service_errors
#     - id: service_errors.stack_id
#   - describe_user_profiles
#     - id: user_profiles.iam_user_arn
# OpsWorksCM
#   - describe_account_attributes
#     - id: attributes.name
#   - describe_backups
#     - id: backups.user_arn
#   - describe_servers
#     - id: servers.cloud_formation_stack_arn
# Organizations
# Pinpoint
# Polly
#   - describe_voices
#     - id: voices.id
#   - list_lexicons
#     - id: lexicons.attributes.lexicon_arn
# RDS
#   - describe_events
#     - id: events.source_arn
#   - describe_certificates
#     - id: certificates.certificate_arn
#   - describe_account_attributes
#     - id: account_quotas.account_quota_name
#   - describe_db_clusters
#     - id: db_clusters.db_cluster_arn
#   - describe_db_engine_versions
#     - id: db_engine_versions.default_character_set.character_set_name
#   - describe_db_cluster_parameter_groups
#     - id: db_cluster_parameter_groups.db_cluster_parameter_group_arn
#   - describe_db_parameter_groups
#     - id: db_parameter_groups.db_parameter_group_arn
#   - describe_db_cluster_snapshots
#     - id: db_cluster_snapshots.source_db_cluster_snapshot_arn
#   - describe_db_security_groups
#     - id: db_security_groups.db_security_group_arn
#   - describe_db_instances
#     - id: db_instances.tde_credential_arn
#   - describe_db_subnet_groups
#     - id: db_subnet_groups.db_subnet_group_arn
#   - describe_db_snapshots
#     - id: db_snapshots.db_snapshot_arn
#   - describe_event_categories
#     - id: event_categories_map_list.source_type
#   - describe_event_subscriptions
#     - id: event_subscriptions_list.event_subscription_arn
#   - describe_option_groups
#     - id: option_groups_list.option_group_arn
#   - describe_reserved_db_instances
#     - id: reserved_db_instances.reserved_db_instance_arn
#   - describe_pending_maintenance_actions
#     - id: pending_maintenance_actions.pending_maintenance_action_details
#   - describe_source_regions
#     - id: source_regions.region_name
#   - describe_reserved_db_instances_offerings
#     - id: reserved_db_instances_offerings.reserved_db_instances_offering_id
# Redshift
#   - describe_clusters
#     - id: clusters.iam_roles.iam_role_arn
#   - describe_events
#     - id: events.event_id
#   - describe_event_categories
#     - id: event_categories_map_list.events.event_id
#   - describe_event_subscriptions
#     - id: event_subscriptions_list.sns_topic_arn
#   - describe_cluster_parameter_groups
#     - id: parameter_groups.parameter_group_name
#   - describe_cluster_snapshots
#     - id: snapshots.kms_key_id
#   - describe_cluster_subnet_groups
#     - id: cluster_subnet_groups.vpc_id
#   - describe_cluster_versions
#     - id: cluster_versions.cluster_version
#   - describe_hsm_client_certificates
#     - id: hsm_client_certificates.hsm_client_certificate_identifier
#   - describe_hsm_configurations
#     - id: hsm_configurations.hsm_partition_name
#   - describe_orderable_cluster_options
#     - id: orderable_cluster_options.cluster_version
#   - describe_reserved_node_offerings
#     - id: reserved_node_offerings.reserved_node_offering_id
#   - describe_reserved_nodes
#     - id: reserved_nodes.reserved_node_id
#   - describe_snapshot_copy_grants
#     - id: snapshot_copy_grants.kms_key_id
# Rekognition
#   - list_collections
#     - id: collection_ids
# ResourceGroupsTaggingAPI
#   - get_tag_keys
#     - id: tag_keys
# Route53
#   - get_checker_ip_ranges
#     - id: checker_ip_ranges
#   - list_geo_locations
#     - id: geo_location_details_list.subdivision_name
#   - list_health_checks
#     - id: health_checks.id
#   - list_hosted_zones
#     - id: hosted_zones.id
#   - list_reusable_delegation_sets
#     - id: delegation_sets.id
#   - list_traffic_policies
#     - id: traffic_policy_summaries.id
#   - list_traffic_policy_instances
#     - id: traffic_policy_instances.id
# Route53Domains
#   - list_domains
#     - id: domains.domain_name
#   - list_operations
#     - id: operations.operation_id
# S3
#   - list_buckets
#     - id: owner.id
# SES
#   - list_identities
#     - id: identities
#   - get_send_statistics
#     - id: send_data_points.timestamp
#   - list_configuration_sets
#     - id: configuration_sets.name
#   - list_receipt_filters
#     - id: filters.name
#   - list_receipt_rule_sets
#     - id: rule_sets.name
#   - list_verified_email_addresses
#     - id: verified_email_addresses
# SMS
#   - get_connectors
#     - id: connector_list.vm_manager_id
#   - get_replication_jobs
#     - id: replication_job_list.replication_job_id
#   - get_servers
#     - id: server_list.server_id
# SNS
#   - get_sms_attributes
#     - id: NA
#   - list_platform_applications
#     - id: platform_applications.platform_application_arn
#   - list_subscriptions
#     - id: subscriptions.topic_arn
#   - list_topics
#     - id: topics.topic_arn
# SQS
#   - list_queues
#     - id: queue_urls
# SSM
#   - describe_maintenance_windows
#     - id: window_identities.window_id
#   - describe_parameters
#     - id: parameters.key_id
#   - describe_patch_baselines
#     - id: baseline_identities.baseline_id
#   - describe_patch_groups
#     - id: mappings.baseline_identity.baseline_id
#   - list_associations
#     - id: associations.instance_id
#   - list_command_invocations
#     - id: command_invocations.notification_config.notification_arn
#   - list_commands
#     - id: commands.notification_config.notification_arn
#   - list_documents
#     - id: document_identifiers.platform_types
#   - describe_activations
#     - id: activation_list.activation_id
#   - describe_automation_executions
#     - id: automation_execution_metadata_list.automation_execution_id
#   - describe_available_patches
#     - id: patches.id
# STS
# SWF
# ServiceCatalog
#   - list_accepted_portfolio_shares
#     - id: portfolio_details.arn
#   - list_portfolios
#     - id: portfolio_details.arn
# Shield
#   - list_attacks
#     - id: attack_summaries.resource_arn
# SimpleDB
#   - list_domains
#     - id: domain_names
# Snowball
#   - describe_addresses
#     - id: addresses.address_id
#   - list_jobs
#     - id: job_list_entries.job_id
#   - list_clusters
#     - id: cluster_list_entries.cluster_id
# States
#   - list_activities
#     - id: activities.activity_arn
#   - list_state_machines
#     - id: state_machines.state_machine_arn
# StorageGateway
#   - describe_tape_archives
#     - id: tape_archives.tape_arn
#   - list_file_shares
#     - id: file_share_info_list.file_share_arn
#   - list_gateways
#     - id: gateways.gateway_arn
#   - list_tapes
#     - id: tape_infos.gateway_arn
#   - list_volumes
#     - id: gateway_arn
# Support
# WAF
#   - list_rules
#     - id: rules.rule_id
#   - list_byte_match_sets
#     - id: byte_match_sets.byte_match_set_id
#   - list_ip_sets
#     - id: ip_sets.ip_set_id
#   - list_size_constraint_sets
#     - id: size_constraint_sets.size_constraint_set_id
#   - list_sql_injection_match_sets
#     - id: sql_injection_match_sets.sql_injection_match_set_id
#   - list_web_acls
#     - id: web_acls.web_acl_id
#   - list_xss_match_sets
#     - id: xss_match_sets.xss_match_set_id
# WAFRegional
#   - list_rules
#     - id: rules.rule_id
#   - list_byte_match_sets
#     - id: byte_match_sets.byte_match_set_id
#   - list_ip_sets
#     - id: ip_sets.ip_set_id
#   - list_size_constraint_sets
#     - id: size_constraint_sets.size_constraint_set_id
#   - list_sql_injection_match_sets
#     - id: sql_injection_match_sets.sql_injection_match_set_id
#   - list_web_acls
#     - id: web_acls.web_acl_id
#   - list_xss_match_sets
#     - id: xss_match_sets.xss_match_set_id
# WorkDocs
# WorkSpaces
#   - describe_workspace_bundles
#     - id: bundles.bundle_id
#   - describe_workspace_directories
#     - id: directories.directory_id
#   - describe_workspaces
#     - id: workspaces.workspace_id
#   - describe_workspaces_connection_status
#     - id: workspaces_connection_status.workspace_id
# XRay
coreo_aws_rule "acm-inventory-certificates" do
  service :ACM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ACM Inventory"
  description "This rule performs an inventory on the ACM service using the list_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_certificates"]
  audit_objects ["object.certificate_summary_list.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificate_summary_list.certificate_arn"]
end
  
coreo_aws_rule_runner "acm-inventory-runner" do
  action :run
  service :ACM
  rules ["acm-inventory-certificates"]
end
coreo_aws_rule "apigateway-inventory-api_keys" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_api_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_api_keys"]
  audit_objects ["object.items.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.id"]
end
coreo_aws_rule "apigateway-inventory-client_certificates" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_client_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_client_certificates"]
  audit_objects ["object.items.client_certificate_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.client_certificate_id"]
end
coreo_aws_rule "apigateway-inventory-domain_names" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_domain_names function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_domain_names"]
  audit_objects ["object.items.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.certificate_arn"]
end
coreo_aws_rule "apigateway-inventory-rest_apis" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_rest_apis function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_rest_apis"]
  audit_objects ["object.items.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.id"]
end
coreo_aws_rule "apigateway-inventory-sdk_types" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_sdk_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_sdk_types"]
  audit_objects ["object.items.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.id"]
end
coreo_aws_rule "apigateway-inventory-usage_plans" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_usage_plans function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_usage_plans"]
  audit_objects ["object.items.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.id"]
end
  
coreo_aws_rule_runner "apigateway-inventory-runner" do
  action :run
  service :APIGateway
  rules ["apigateway-inventory-api_keys", "apigateway-inventory-client_certificates", "apigateway-inventory-domain_names", "apigateway-inventory-rest_apis", "apigateway-inventory-sdk_types", "apigateway-inventory-usage_plans"]
end
coreo_aws_rule "appstream-inventory-images" do
  service :AppStream
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AppStream Inventory"
  description "This rule performs an inventory on the AppStream service using the describe_images function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_images"]
  audit_objects ["object.images.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.images.arn"]
end
coreo_aws_rule "appstream-inventory-fleets" do
  service :AppStream
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AppStream Inventory"
  description "This rule performs an inventory on the AppStream service using the describe_fleets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_fleets"]
  audit_objects ["object.fleets.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.fleets.arn"]
end
coreo_aws_rule "appstream-inventory-stacks" do
  service :AppStream
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AppStream Inventory"
  description "This rule performs an inventory on the AppStream service using the describe_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_stacks"]
  audit_objects ["object.stacks.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.stacks.arn"]
end
  
coreo_aws_rule_runner "appstream-inventory-runner" do
  action :run
  service :AppStream
  rules ["appstream-inventory-images", "appstream-inventory-fleets", "appstream-inventory-stacks"]
end
coreo_aws_rule "autoscaling-inventory-scaling_activities" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_scaling_activities function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_scaling_activities"]
  audit_objects ["object.activities.activity_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.activities.activity_id"]
end
coreo_aws_rule "autoscaling-inventory-adjustment_types" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_adjustment_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_adjustment_types"]
  audit_objects ["object.adjustment_types.adjustment_type"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.adjustment_types.adjustment_type"]
end
coreo_aws_rule "autoscaling-inventory-auto_scaling_groups" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_auto_scaling_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_auto_scaling_groups"]
  audit_objects ["object.auto_scaling_groups.auto_scaling_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.auto_scaling_groups.auto_scaling_group_arn"]
end
coreo_aws_rule "autoscaling-inventory-auto_scaling_instances" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_auto_scaling_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_auto_scaling_instances"]
  audit_objects ["object.auto_scaling_instances.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.auto_scaling_instances.instance_id"]
end
coreo_aws_rule "autoscaling-inventory-auto_scaling_notification_types" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_auto_scaling_notification_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_auto_scaling_notification_types"]
  audit_objects ["object.auto_scaling_notification_types"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.auto_scaling_notification_types"]
end
coreo_aws_rule "autoscaling-inventory-launch_configurations" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_launch_configurations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_launch_configurations"]
  audit_objects ["object.launch_configurations.launch_configuration_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.launch_configurations.launch_configuration_arn"]
end
coreo_aws_rule "autoscaling-inventory-lifecycle_hook_types" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_lifecycle_hook_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_lifecycle_hook_types"]
  audit_objects ["object.lifecycle_hook_types"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.lifecycle_hook_types"]
end
coreo_aws_rule "autoscaling-inventory-metric_collection_types" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_metric_collection_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_metric_collection_types"]
  audit_objects ["object.metrics.metric"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.metrics.metric"]
end
coreo_aws_rule "autoscaling-inventory-notification_configurations" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_notification_configurations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_notification_configurations"]
  audit_objects ["object.notification_configurations.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.notification_configurations.topic_arn"]
end
coreo_aws_rule "autoscaling-inventory-policies" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_policies"]
  audit_objects ["object.scaling_policies.policy_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.scaling_policies.policy_arn"]
end
coreo_aws_rule "autoscaling-inventory-scaling_process_types" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_scaling_process_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_scaling_process_types"]
  audit_objects ["object.processes.process_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.processes.process_name"]
end
coreo_aws_rule "autoscaling-inventory-scheduled_actions" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_scheduled_actions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_scheduled_actions"]
  audit_objects ["object.scheduled_update_group_actions.scheduled_action_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.scheduled_update_group_actions.scheduled_action_arn"]
end
coreo_aws_rule "autoscaling-inventory-termination_policy_types" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_termination_policy_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_termination_policy_types"]
  audit_objects ["object.termination_policy_types"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.termination_policy_types"]
end
  
coreo_aws_rule_runner "autoscaling-inventory-runner" do
  action :run
  service :AutoScaling
  rules ["autoscaling-inventory-scaling_activities", "autoscaling-inventory-adjustment_types", "autoscaling-inventory-auto_scaling_groups", "autoscaling-inventory-auto_scaling_instances", "autoscaling-inventory-auto_scaling_notification_types", "autoscaling-inventory-launch_configurations", "autoscaling-inventory-lifecycle_hook_types", "autoscaling-inventory-metric_collection_types", "autoscaling-inventory-notification_configurations", "autoscaling-inventory-policies", "autoscaling-inventory-scaling_process_types", "autoscaling-inventory-scheduled_actions", "autoscaling-inventory-termination_policy_types"]
end
coreo_aws_rule "batch-inventory-compute_environments" do
  service :Batch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Batch Inventory"
  description "This rule performs an inventory on the Batch service using the describe_compute_environments function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_compute_environments"]
  audit_objects ["object.compute_environments.compute_environment_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.compute_environments.compute_environment_arn"]
end
coreo_aws_rule "batch-inventory-job_definitions" do
  service :Batch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Batch Inventory"
  description "This rule performs an inventory on the Batch service using the describe_job_definitions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_job_definitions"]
  audit_objects ["object.job_definitions.job_definition_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.job_definitions.job_definition_arn"]
end
coreo_aws_rule "batch-inventory-job_queues" do
  service :Batch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Batch Inventory"
  description "This rule performs an inventory on the Batch service using the describe_job_queues function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_job_queues"]
  audit_objects ["object.job_queues.job_queue_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.job_queues.job_queue_arn"]
end
  
coreo_aws_rule_runner "batch-inventory-runner" do
  action :run
  service :Batch
  rules ["batch-inventory-compute_environments", "batch-inventory-job_definitions", "batch-inventory-job_queues"]
end
coreo_aws_rule "clouddirectory-inventory-development_schema_arns" do
  service :CloudDirectory
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudDirectory Inventory"
  description "This rule performs an inventory on the CloudDirectory service using the list_development_schema_arns function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_development_schema_arns"]
  audit_objects ["object.schema_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.schema_arns"]
end
coreo_aws_rule "clouddirectory-inventory-directories" do
  service :CloudDirectory
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudDirectory Inventory"
  description "This rule performs an inventory on the CloudDirectory service using the list_directories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_directories"]
  audit_objects ["object.directories.directory_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.directories.directory_arn"]
end
coreo_aws_rule "clouddirectory-inventory-published_schema_arns" do
  service :CloudDirectory
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudDirectory Inventory"
  description "This rule performs an inventory on the CloudDirectory service using the list_published_schema_arns function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_published_schema_arns"]
  audit_objects ["object.schema_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.schema_arns"]
end
  
coreo_aws_rule_runner "clouddirectory-inventory-runner" do
  action :run
  service :CloudDirectory
  rules ["clouddirectory-inventory-development_schema_arns", "clouddirectory-inventory-directories", "clouddirectory-inventory-published_schema_arns"]
end
coreo_aws_rule "cloudformation-inventory-stacks" do
  service :CloudFormation
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFormation Inventory"
  description "This rule performs an inventory on the CloudFormation service using the describe_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_stacks"]
  audit_objects ["object.stacks.role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.stacks.role_arn"]
end
coreo_aws_rule "cloudformation-inventory-account_limits" do
  service :CloudFormation
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFormation Inventory"
  description "This rule performs an inventory on the CloudFormation service using the describe_account_limits function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_account_limits"]
  audit_objects ["object.account_limits.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.account_limits.name"]
end
coreo_aws_rule "cloudformation-inventory-exports" do
  service :CloudFormation
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFormation Inventory"
  description "This rule performs an inventory on the CloudFormation service using the list_exports function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_exports"]
  audit_objects ["object.exports.exporting_stack_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.exports.exporting_stack_id"]
end
coreo_aws_rule "cloudformation-inventory-stacks" do
  service :CloudFormation
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFormation Inventory"
  description "This rule performs an inventory on the CloudFormation service using the list_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_stacks"]
  audit_objects ["object.stack_summaries.stack_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.stack_summaries.stack_id"]
end
  
coreo_aws_rule_runner "cloudformation-inventory-runner" do
  action :run
  service :CloudFormation
  rules ["cloudformation-inventory-stacks", "cloudformation-inventory-account_limits", "cloudformation-inventory-exports", "cloudformation-inventory-stacks"]
end
coreo_aws_rule "cloudfront-inventory-cloud_front_origin_access_identities" do
  service :CloudFront
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFront Inventory"
  description "This rule performs an inventory on the CloudFront service using the list_cloud_front_origin_access_identities function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_cloud_front_origin_access_identities"]
  audit_objects ["object.cloud_front_origin_access_identity_list.items.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cloud_front_origin_access_identity_list.items.id"]
end
coreo_aws_rule "cloudfront-inventory-distributions" do
  service :CloudFront
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFront Inventory"
  description "This rule performs an inventory on the CloudFront service using the list_distributions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_distributions"]
  audit_objects ["object.distribution_list.items.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.distribution_list.items.arn"]
end
coreo_aws_rule "cloudfront-inventory-streaming_distributions" do
  service :CloudFront
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFront Inventory"
  description "This rule performs an inventory on the CloudFront service using the list_streaming_distributions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_streaming_distributions"]
  audit_objects ["object.streaming_distribution_list.items.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.streaming_distribution_list.items.arn"]
end
  
coreo_aws_rule_runner "cloudfront-inventory-runner" do
  action :run
  service :CloudFront
  rules ["cloudfront-inventory-cloud_front_origin_access_identities", "cloudfront-inventory-distributions", "cloudfront-inventory-streaming_distributions"]
end
coreo_aws_rule "cloudhsm-inventory-available_zones" do
  service :CloudHSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudHSM Inventory"
  description "This rule performs an inventory on the CloudHSM service using the list_available_zones function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_available_zones"]
  audit_objects ["object.az_list"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.az_list"]
end
coreo_aws_rule "cloudhsm-inventory-hapgs" do
  service :CloudHSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudHSM Inventory"
  description "This rule performs an inventory on the CloudHSM service using the list_hapgs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_hapgs"]
  audit_objects ["object.hapg_list"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.hapg_list"]
end
coreo_aws_rule "cloudhsm-inventory-hsms" do
  service :CloudHSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudHSM Inventory"
  description "This rule performs an inventory on the CloudHSM service using the list_hsms function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_hsms"]
  audit_objects ["object.hsm_list"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.hsm_list"]
end
coreo_aws_rule "cloudhsm-inventory-luna_clients" do
  service :CloudHSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudHSM Inventory"
  description "This rule performs an inventory on the CloudHSM service using the list_luna_clients function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_luna_clients"]
  audit_objects ["object.client_list"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.client_list"]
end
  
coreo_aws_rule_runner "cloudhsm-inventory-runner" do
  action :run
  service :CloudHSM
  rules ["cloudhsm-inventory-available_zones", "cloudhsm-inventory-hapgs", "cloudhsm-inventory-hsms", "cloudhsm-inventory-luna_clients"]
end
coreo_aws_rule "cloudsearch-inventory-domains" do
  service :CloudSearch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudSearch Inventory"
  description "This rule performs an inventory on the CloudSearch service using the describe_domains function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_domains"]
  audit_objects ["object.domain_status_list.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.domain_status_list.arn"]
end
  
coreo_aws_rule_runner "cloudsearch-inventory-runner" do
  action :run
  service :CloudSearch
  rules ["cloudsearch-inventory-domains"]
end
coreo_aws_rule "cloudtrail-inventory-trails" do
  service :CloudTrail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudTrail Inventory"
  description "This rule performs an inventory on the CloudTrail service using the describe_trails function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_trails"]
  audit_objects ["object.trail_list.trail_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.trail_list.trail_arn"]
end
coreo_aws_rule "cloudtrail-inventory-public_keys" do
  service :CloudTrail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudTrail Inventory"
  description "This rule performs an inventory on the CloudTrail service using the list_public_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_public_keys"]
  audit_objects ["object.public_key_list.value"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.public_key_list.value"]
end
  
coreo_aws_rule_runner "cloudtrail-inventory-runner" do
  action :run
  service :CloudTrail
  rules ["cloudtrail-inventory-trails", "cloudtrail-inventory-public_keys"]
end
coreo_aws_rule "cloudwatch-inventory-alarms" do
  service :CloudWatch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatch Inventory"
  description "This rule performs an inventory on the CloudWatch service using the describe_alarms function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_alarms"]
  audit_objects ["object.metric_alarms.alarm_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.metric_alarms.alarm_arn"]
end
coreo_aws_rule "cloudwatch-inventory-metrics" do
  service :CloudWatch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatch Inventory"
  description "This rule performs an inventory on the CloudWatch service using the list_metrics function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_metrics"]
  audit_objects ["object.metrics.metric_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.metrics.metric_name"]
end
  
coreo_aws_rule_runner "cloudwatch-inventory-runner" do
  action :run
  service :CloudWatch
  rules ["cloudwatch-inventory-alarms", "cloudwatch-inventory-metrics"]
end
coreo_aws_rule "cloudwatchevents-inventory-rules" do
  service :CloudWatchEvents
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchEvents Inventory"
  description "This rule performs an inventory on the CloudWatchEvents service using the list_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_rules"]
  audit_objects ["object.rules.role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rules.role_arn"]
end
  
coreo_aws_rule_runner "cloudwatchevents-inventory-runner" do
  action :run
  service :CloudWatchEvents
  rules ["cloudwatchevents-inventory-rules"]
end
coreo_aws_rule "cloudwatchlogs-inventory-export_tasks" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Inventory"
  description "This rule performs an inventory on the CloudWatchLogs service using the describe_export_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_export_tasks"]
  audit_objects ["object.export_tasks.task_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.export_tasks.task_id"]
end
coreo_aws_rule "cloudwatchlogs-inventory-destinations" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Inventory"
  description "This rule performs an inventory on the CloudWatchLogs service using the describe_destinations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_destinations"]
  audit_objects ["object.destinations.role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.destinations.role_arn"]
end
coreo_aws_rule "cloudwatchlogs-inventory-log_groups" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Inventory"
  description "This rule performs an inventory on the CloudWatchLogs service using the describe_log_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_log_groups"]
  audit_objects ["object.log_groups.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.log_groups.arn"]
end
coreo_aws_rule "cloudwatchlogs-inventory-metric_filters" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Inventory"
  description "This rule performs an inventory on the CloudWatchLogs service using the describe_metric_filters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_metric_filters"]
  audit_objects ["object.metric_filters.filter_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.metric_filters.filter_name"]
end
  
coreo_aws_rule_runner "cloudwatchlogs-inventory-runner" do
  action :run
  service :CloudWatchLogs
  rules ["cloudwatchlogs-inventory-export_tasks", "cloudwatchlogs-inventory-destinations", "cloudwatchlogs-inventory-log_groups", "cloudwatchlogs-inventory-metric_filters"]
end
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.ids"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ids"]
end
coreo_aws_rule "codebuild-inventory-curated_environment_images" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_curated_environment_images function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_curated_environment_images"]
  audit_objects ["object.platforms.platform"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.platforms.platform"]
end
coreo_aws_rule "codebuild-inventory-projects" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Inventory"
  description "This rule performs an inventory on the CodeBuild service using the list_projects function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_projects"]
  audit_objects ["object.projects"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.projects"]
end
  
coreo_aws_rule_runner "codebuild-inventory-runner" do
  action :run
  service :CodeBuild
  rules ["codebuild-inventory-builds", "codebuild-inventory-curated_environment_images", "codebuild-inventory-projects"]
end
coreo_aws_rule "codecommit-inventory-repositories" do
  service :CodeCommit
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeCommit Inventory"
  description "This rule performs an inventory on the CodeCommit service using the list_repositories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_repositories"]
  audit_objects ["object.repositories.repository_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.repositories.repository_id"]
end
  
coreo_aws_rule_runner "codecommit-inventory-runner" do
  action :run
  service :CodeCommit
  rules ["codecommit-inventory-repositories"]
end
coreo_aws_rule "codedeploy-inventory-applications" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy Inventory"
  description "This rule performs an inventory on the CodeDeploy service using the list_applications function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_applications"]
  audit_objects ["object.applications"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.applications"]
end
coreo_aws_rule "codedeploy-inventory-deployment_configs" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy Inventory"
  description "This rule performs an inventory on the CodeDeploy service using the list_deployment_configs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_deployment_configs"]
  audit_objects ["object.deployment_configs_list"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.deployment_configs_list"]
end
coreo_aws_rule "codedeploy-inventory-deployments" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy Inventory"
  description "This rule performs an inventory on the CodeDeploy service using the list_deployments function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_deployments"]
  audit_objects ["object.deployments"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.deployments"]
end
coreo_aws_rule "codedeploy-inventory-on_premises_instances" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy Inventory"
  description "This rule performs an inventory on the CodeDeploy service using the list_on_premises_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_on_premises_instances"]
  audit_objects ["object.instance_names"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instance_names"]
end
  
coreo_aws_rule_runner "codedeploy-inventory-runner" do
  action :run
  service :CodeDeploy
  rules ["codedeploy-inventory-applications", "codedeploy-inventory-deployment_configs", "codedeploy-inventory-deployments", "codedeploy-inventory-on_premises_instances"]
end
coreo_aws_rule "codepipeline-inventory-action_types" do
  service :CodePipeline
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodePipeline Inventory"
  description "This rule performs an inventory on the CodePipeline service using the list_action_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_action_types"]
  audit_objects ["object.action_types.id.owner"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.action_types.id.owner"]
end
coreo_aws_rule "codepipeline-inventory-pipelines" do
  service :CodePipeline
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodePipeline Inventory"
  description "This rule performs an inventory on the CodePipeline service using the list_pipelines function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_pipelines"]
  audit_objects ["object.pipelines.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.pipelines.name"]
end
  
coreo_aws_rule_runner "codepipeline-inventory-runner" do
  action :run
  service :CodePipeline
  rules ["codepipeline-inventory-action_types", "codepipeline-inventory-pipelines"]
end
coreo_aws_rule "codestar-inventory-projects" do
  service :CodeStar
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeStar Inventory"
  description "This rule performs an inventory on the CodeStar service using the list_projects function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_projects"]
  audit_objects ["object.projects.project_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.projects.project_arn"]
end
coreo_aws_rule "codestar-inventory-user_profiles" do
  service :CodeStar
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeStar Inventory"
  description "This rule performs an inventory on the CodeStar service using the list_user_profiles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_user_profiles"]
  audit_objects ["object.user_profiles.user_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.user_profiles.user_arn"]
end
  
coreo_aws_rule_runner "codestar-inventory-runner" do
  action :run
  service :CodeStar
  rules ["codestar-inventory-projects", "codestar-inventory-user_profiles"]
end
coreo_aws_rule "configservice-inventory-config_rule_evaluation_status" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_config_rule_evaluation_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_config_rule_evaluation_status"]
  audit_objects ["object.config_rules_evaluation_status.config_rule_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.config_rules_evaluation_status.config_rule_arn"]
end
coreo_aws_rule "configservice-inventory-config_rules" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_config_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_config_rules"]
  audit_objects ["object.config_rules.config_rule_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.config_rules.config_rule_arn"]
end
coreo_aws_rule "configservice-inventory-configuration_recorder_status" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_configuration_recorder_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_configuration_recorder_status"]
  audit_objects ["object.configuration_recorders_status.last_status_change_time"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.configuration_recorders_status.last_status_change_time"]
end
coreo_aws_rule "configservice-inventory-configuration_recorders" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_configuration_recorders function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_configuration_recorders"]
  audit_objects ["object.configuration_recorders.role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.configuration_recorders.role_arn"]
end
coreo_aws_rule "configservice-inventory-delivery_channel_status" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_delivery_channel_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_delivery_channel_status"]
  audit_objects ["object.delivery_channels_status.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.delivery_channels_status.name"]
end
coreo_aws_rule "configservice-inventory-delivery_channels" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_delivery_channels function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_delivery_channels"]
  audit_objects ["object.delivery_channels.sns_topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.delivery_channels.sns_topic_arn"]
end
  
coreo_aws_rule_runner "configservice-inventory-runner" do
  action :run
  service :ConfigService
  rules ["configservice-inventory-config_rule_evaluation_status", "configservice-inventory-config_rules", "configservice-inventory-configuration_recorder_status", "configservice-inventory-configuration_recorders", "configservice-inventory-delivery_channel_status", "configservice-inventory-delivery_channels"]
end
coreo_aws_rule "datapipeline-inventory-pipelines" do
  service :DataPipeline
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DataPipeline Inventory"
  description "This rule performs an inventory on the DataPipeline service using the list_pipelines function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_pipelines"]
  audit_objects ["object.pipeline_id_list.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.pipeline_id_list.id"]
end
  
coreo_aws_rule_runner "datapipeline-inventory-runner" do
  action :run
  service :DataPipeline
  rules ["datapipeline-inventory-pipelines"]
end
coreo_aws_rule "databasemigrationservice-inventory-account_attributes" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_account_attributes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_account_attributes"]
  audit_objects ["object.account_quotas.account_quota_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.account_quotas.account_quota_name"]
end
coreo_aws_rule "databasemigrationservice-inventory-certificates" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_certificates"]
  audit_objects ["object.certificates.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificates.certificate_arn"]
end
coreo_aws_rule "databasemigrationservice-inventory-connections" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_connections"]
  audit_objects ["object.connections.endpoint_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.connections.endpoint_arn"]
end
coreo_aws_rule "databasemigrationservice-inventory-endpoint_types" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_endpoint_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_endpoint_types"]
  audit_objects ["object.supported_endpoint_types.engine_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.supported_endpoint_types.engine_name"]
end
coreo_aws_rule "databasemigrationservice-inventory-endpoints" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_endpoints function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_endpoints"]
  audit_objects ["object.endpoints.endpoint_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.endpoints.endpoint_arn"]
end
coreo_aws_rule "databasemigrationservice-inventory-orderable_replication_instances" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_orderable_replication_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_orderable_replication_instances"]
  audit_objects ["object.orderable_replication_instances.min_allocated_storage"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.orderable_replication_instances.min_allocated_storage"]
end
coreo_aws_rule "databasemigrationservice-inventory-replication_instances" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_replication_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_replication_instances"]
  audit_objects ["object.replication_instances.replication_instance_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.replication_instances.replication_instance_arn"]
end
coreo_aws_rule "databasemigrationservice-inventory-replication_subnet_groups" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_replication_subnet_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_replication_subnet_groups"]
  audit_objects ["object.replication_subnet_groups.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.replication_subnet_groups.vpc_id"]
end
coreo_aws_rule "databasemigrationservice-inventory-replication_tasks" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_replication_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_replication_tasks"]
  audit_objects ["object.replication_tasks.source_endpoint_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.replication_tasks.source_endpoint_arn"]
end
  
coreo_aws_rule_runner "databasemigrationservice-inventory-runner" do
  action :run
  service :DatabaseMigrationService
  rules ["databasemigrationservice-inventory-account_attributes", "databasemigrationservice-inventory-certificates", "databasemigrationservice-inventory-connections", "databasemigrationservice-inventory-endpoint_types", "databasemigrationservice-inventory-endpoints", "databasemigrationservice-inventory-orderable_replication_instances", "databasemigrationservice-inventory-replication_instances", "databasemigrationservice-inventory-replication_subnet_groups", "databasemigrationservice-inventory-replication_tasks"]
end
coreo_aws_rule "directconnect-inventory-connections" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_connections"]
  audit_objects ["object.connections.lag_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.connections.lag_id"]
end
coreo_aws_rule "directconnect-inventory-lags" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_lags function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_lags"]
  audit_objects ["object.lags.lag_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.lags.lag_id"]
end
coreo_aws_rule "directconnect-inventory-locations" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_locations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_locations"]
  audit_objects ["object.locations.location_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.locations.location_name"]
end
coreo_aws_rule "directconnect-inventory-virtual_gateways" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_virtual_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_virtual_gateways"]
  audit_objects ["object.virtual_gateways.virtual_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.virtual_gateways.virtual_gateway_id"]
end
coreo_aws_rule "directconnect-inventory-virtual_interfaces" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_virtual_interfaces function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_virtual_interfaces"]
  audit_objects ["object.virtual_interfaces.virtual_interface_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.virtual_interfaces.virtual_interface_id"]
end
  
coreo_aws_rule_runner "directconnect-inventory-runner" do
  action :run
  service :DirectConnect
  rules ["directconnect-inventory-connections", "directconnect-inventory-lags", "directconnect-inventory-locations", "directconnect-inventory-virtual_gateways", "directconnect-inventory-virtual_interfaces"]
end
coreo_aws_rule "directoryservice-inventory-snapshots" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_snapshots"]
  audit_objects ["object.snapshots.snapshot_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshots.snapshot_id"]
end
coreo_aws_rule "directoryservice-inventory-directories" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_directories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_directories"]
  audit_objects ["object.directory_descriptions.directory_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.directory_descriptions.directory_id"]
end
coreo_aws_rule "directoryservice-inventory-event_topics" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_event_topics function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_topics"]
  audit_objects ["object.event_topics.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_topics.topic_arn"]
end
coreo_aws_rule "directoryservice-inventory-trusts" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_trusts function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_trusts"]
  audit_objects ["object.trusts.trust_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.trusts.trust_id"]
end
  
coreo_aws_rule_runner "directoryservice-inventory-runner" do
  action :run
  service :DirectoryService
  rules ["directoryservice-inventory-snapshots", "directoryservice-inventory-directories", "directoryservice-inventory-event_topics", "directoryservice-inventory-trusts"]
end
coreo_aws_rule "dynamodb-inventory-tables" do
  service :DynamoDB
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DynamoDB Inventory"
  description "This rule performs an inventory on the DynamoDB service using the list_tables function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_tables"]
  audit_objects ["object.last_evaluated_table_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.last_evaluated_table_name"]
end
  
coreo_aws_rule_runner "dynamodb-inventory-runner" do
  action :run
  service :DynamoDB
  rules ["dynamodb-inventory-tables"]
end
coreo_aws_rule "dynamodbstreams-inventory-streams" do
  service :DynamoDBStreams
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DynamoDBStreams Inventory"
  description "This rule performs an inventory on the DynamoDBStreams service using the list_streams function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_streams"]
  audit_objects ["object.last_evaluated_stream_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.last_evaluated_stream_arn"]
end
  
coreo_aws_rule_runner "dynamodbstreams-inventory-runner" do
  action :run
  service :DynamoDBStreams
  rules ["dynamodbstreams-inventory-streams"]
end
coreo_aws_rule "ec2-inventory-account_attributes" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_account_attributes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_account_attributes"]
  audit_objects ["object.account_attributes.attribute_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.account_attributes.attribute_name"]
end
coreo_aws_rule "ec2-inventory-addresses" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_addresses function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_addresses"]
  audit_objects ["object.addresses.allocation_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.addresses.allocation_id"]
end
coreo_aws_rule "ec2-inventory-availability_zones" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_availability_zones function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_availability_zones"]
  audit_objects ["object.availability_zones.region_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.availability_zones.region_name"]
end
coreo_aws_rule "ec2-inventory-bundle_tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_bundle_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_bundle_tasks"]
  audit_objects ["object.bundle_tasks.bundle_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.bundle_tasks.bundle_id"]
end
coreo_aws_rule "ec2-inventory-classic_link_instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_classic_link_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_classic_link_instances"]
  audit_objects ["object.instances.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instances.instance_id"]
end
coreo_aws_rule "ec2-inventory-conversion_tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_conversion_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_conversion_tasks"]
  audit_objects ["object.conversion_tasks.import_volume.volume.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.conversion_tasks.import_volume.volume.id"]
end
coreo_aws_rule "ec2-inventory-customer_gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_customer_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_customer_gateways"]
  audit_objects ["object.customer_gateways.customer_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.customer_gateways.customer_gateway_id"]
end
coreo_aws_rule "ec2-inventory-dhcp_options" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_dhcp_options function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_dhcp_options"]
  audit_objects ["object.dhcp_options.dhcp_options_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.dhcp_options.dhcp_options_id"]
end
coreo_aws_rule "ec2-inventory-egress_only_internet_gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_egress_only_internet_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_egress_only_internet_gateways"]
  audit_objects ["object.egress_only_internet_gateways.egress_only_internet_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.egress_only_internet_gateways.egress_only_internet_gateway_id"]
end
coreo_aws_rule "ec2-inventory-export_tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_export_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_export_tasks"]
  audit_objects ["object.export_tasks.export_task_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.export_tasks.export_task_id"]
end
coreo_aws_rule "ec2-inventory-flow_logs" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_flow_logs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_flow_logs"]
  audit_objects ["object.flow_logs.deliver_logs_permission_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.flow_logs.deliver_logs_permission_arn"]
end
coreo_aws_rule "ec2-inventory-host_reservations" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_host_reservations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_host_reservations"]
  audit_objects ["object.host_reservation_set.offering_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.host_reservation_set.offering_id"]
end
coreo_aws_rule "ec2-inventory-hosts" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_hosts function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_hosts"]
  audit_objects ["object.hosts.host_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.hosts.host_id"]
end
coreo_aws_rule "ec2-inventory-iam_instance_profile_associations" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_iam_instance_profile_associations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_iam_instance_profile_associations"]
  audit_objects ["object.iam_instance_profile_associations.iam_instance_profile.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.iam_instance_profile_associations.iam_instance_profile.arn"]
end
coreo_aws_rule "ec2-inventory-images" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_images function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_images"]
  audit_objects ["object.images.image_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.images.image_id"]
end
coreo_aws_rule "ec2-inventory-import_image_tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_import_image_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_import_image_tasks"]
  audit_objects ["object.import_image_tasks.import_task_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.import_image_tasks.import_task_id"]
end
coreo_aws_rule "ec2-inventory-import_snapshot_tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_import_snapshot_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_import_snapshot_tasks"]
  audit_objects ["object.import_snapshot_tasks.import_task_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.import_snapshot_tasks.import_task_id"]
end
coreo_aws_rule "ec2-inventory-instance_status" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_instance_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_instance_status"]
  audit_objects ["object.instance_statuses.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instance_statuses.instance_id"]
end
coreo_aws_rule "ec2-inventory-instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_instances"]
  audit_objects ["object.reservations.instances.iam_instance_profile.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reservations.instances.iam_instance_profile.arn"]
end
coreo_aws_rule "ec2-inventory-internet_gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_internet_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_internet_gateways"]
  audit_objects ["object.internet_gateways.internet_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.internet_gateways.internet_gateway_id"]
end
coreo_aws_rule "ec2-inventory-key_pairs" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_key_pairs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_key_pairs"]
  audit_objects ["object.key_pairs.key_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.key_pairs.key_name"]
end
coreo_aws_rule "ec2-inventory-moving_addresses" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_moving_addresses function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_moving_addresses"]
  audit_objects ["object.moving_address_statuses.public_ip"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.moving_address_statuses.public_ip"]
end
coreo_aws_rule "ec2-inventory-nat_gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_nat_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_nat_gateways"]
  audit_objects ["object.nat_gateways.subnet_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.nat_gateways.subnet_id"]
end
coreo_aws_rule "ec2-inventory-network_acls" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_network_acls function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_network_acls"]
  audit_objects ["object.network_acls.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.network_acls.vpc_id"]
end
coreo_aws_rule "ec2-inventory-network_interfaces" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_network_interfaces function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_network_interfaces"]
  audit_objects ["object.network_interfaces.subnet_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.network_interfaces.subnet_id"]
end
coreo_aws_rule "ec2-inventory-placement_groups" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_placement_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_placement_groups"]
  audit_objects ["object.placement_groups.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.placement_groups.group_name"]
end
coreo_aws_rule "ec2-inventory-prefix_lists" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_prefix_lists function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_prefix_lists"]
  audit_objects ["object.prefix_lists.prefix_list_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.prefix_lists.prefix_list_id"]
end
coreo_aws_rule "ec2-inventory-reserved_instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_reserved_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_instances"]
  audit_objects ["object.reserved_instances.reserved_instances_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_instances.reserved_instances_id"]
end
coreo_aws_rule "ec2-inventory-reserved_instances_modifications" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_reserved_instances_modifications function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_instances_modifications"]
  audit_objects ["object.reserved_instances_modifications.reserved_instances_modification_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_instances_modifications.reserved_instances_modification_id"]
end
coreo_aws_rule "ec2-inventory-reserved_instances_offerings" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_reserved_instances_offerings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_instances_offerings"]
  audit_objects ["object.reserved_instances_offerings.reserved_instances_offering_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_instances_offerings.reserved_instances_offering_id"]
end
coreo_aws_rule "ec2-inventory-route_tables" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_route_tables function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_route_tables"]
  audit_objects ["object.route_tables.route_table_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.route_tables.route_table_id"]
end
coreo_aws_rule "ec2-inventory-scheduled_instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_scheduled_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_scheduled_instances"]
  audit_objects ["object.scheduled_instance_set.scheduled_instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.scheduled_instance_set.scheduled_instance_id"]
end
coreo_aws_rule "ec2-inventory-security_groups" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_security_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_security_groups"]
  audit_objects ["object.security_groups.group_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.security_groups.group_id"]
end
coreo_aws_rule "ec2-inventory-snapshots" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_snapshots"]
  audit_objects ["object.snapshots.data_encryption_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshots.data_encryption_key_id"]
end
coreo_aws_rule "ec2-inventory-spot_fleet_requests" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_spot_fleet_requests function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_spot_fleet_requests"]
  audit_objects ["object.spot_fleet_request_configs.spot_fleet_request_config.launch_specifications.iam_instance_profile.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.spot_fleet_request_configs.spot_fleet_request_config.launch_specifications.iam_instance_profile.arn"]
end
coreo_aws_rule "ec2-inventory-spot_instance_requests" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_spot_instance_requests function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_spot_instance_requests"]
  audit_objects ["object.spot_instance_requests.launch_specification.iam_instance_profile.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.spot_instance_requests.launch_specification.iam_instance_profile.arn"]
end
coreo_aws_rule "ec2-inventory-subnets" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_subnets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_subnets"]
  audit_objects ["object.subnets.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.subnets.vpc_id"]
end
coreo_aws_rule "ec2-inventory-volume_status" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_volume_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_volume_status"]
  audit_objects ["object.volume_statuses.volume_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.volume_statuses.volume_id"]
end
coreo_aws_rule "ec2-inventory-volumes" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_volumes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_volumes"]
  audit_objects ["object.volumes.volume_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.volumes.volume_id"]
end
coreo_aws_rule "ec2-inventory-volumes_modifications" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_volumes_modifications function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_volumes_modifications"]
  audit_objects ["object.volumes_modifications.volume_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.volumes_modifications.volume_id"]
end
coreo_aws_rule "ec2-inventory-vpc_endpoint_services" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpc_endpoint_services function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpc_endpoint_services"]
  audit_objects ["object.service_names"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.service_names"]
end
coreo_aws_rule "ec2-inventory-vpc_endpoints" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpc_endpoints function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpc_endpoints"]
  audit_objects ["object.vpc_endpoints.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpc_endpoints.vpc_id"]
end
coreo_aws_rule "ec2-inventory-vpc_peering_connections" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpc_peering_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpc_peering_connections"]
  audit_objects ["object.vpc_peering_connections.vpc_peering_connection_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpc_peering_connections.vpc_peering_connection_id"]
end
coreo_aws_rule "ec2-inventory-vpcs" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpcs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpcs"]
  audit_objects ["object.vpcs.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpcs.vpc_id"]
end
coreo_aws_rule "ec2-inventory-vpn_connections" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpn_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpn_connections"]
  audit_objects ["object.vpn_connections.vpn_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpn_connections.vpn_gateway_id"]
end
coreo_aws_rule "ec2-inventory-vpn_gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpn_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpn_gateways"]
  audit_objects ["object.vpn_gateways.vpn_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpn_gateways.vpn_gateway_id"]
end
coreo_aws_rule "ec2-inventory-regions" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_regions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_regions"]
  audit_objects ["object.regions.region_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.regions.region_name"]
end
  
coreo_aws_rule_runner "ec2-inventory-runner" do
  action :run
  service :EC2
  rules ["ec2-inventory-account_attributes", "ec2-inventory-addresses", "ec2-inventory-availability_zones", "ec2-inventory-bundle_tasks", "ec2-inventory-classic_link_instances", "ec2-inventory-conversion_tasks", "ec2-inventory-customer_gateways", "ec2-inventory-dhcp_options", "ec2-inventory-egress_only_internet_gateways", "ec2-inventory-export_tasks", "ec2-inventory-flow_logs", "ec2-inventory-host_reservations", "ec2-inventory-hosts", "ec2-inventory-iam_instance_profile_associations", "ec2-inventory-images", "ec2-inventory-import_image_tasks", "ec2-inventory-import_snapshot_tasks", "ec2-inventory-instance_status", "ec2-inventory-instances", "ec2-inventory-internet_gateways", "ec2-inventory-key_pairs", "ec2-inventory-moving_addresses", "ec2-inventory-nat_gateways", "ec2-inventory-network_acls", "ec2-inventory-network_interfaces", "ec2-inventory-placement_groups", "ec2-inventory-prefix_lists", "ec2-inventory-reserved_instances", "ec2-inventory-reserved_instances_modifications", "ec2-inventory-reserved_instances_offerings", "ec2-inventory-route_tables", "ec2-inventory-scheduled_instances", "ec2-inventory-security_groups", "ec2-inventory-snapshots", "ec2-inventory-spot_fleet_requests", "ec2-inventory-spot_instance_requests", "ec2-inventory-subnets", "ec2-inventory-volume_status", "ec2-inventory-volumes", "ec2-inventory-volumes_modifications", "ec2-inventory-vpc_endpoint_services", "ec2-inventory-vpc_endpoints", "ec2-inventory-vpc_peering_connections", "ec2-inventory-vpcs", "ec2-inventory-vpn_connections", "ec2-inventory-vpn_gateways", "ec2-inventory-regions"]
end
coreo_aws_rule "ecr-inventory-repositories" do
  service :ECR
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECR Inventory"
  description "This rule performs an inventory on the ECR service using the describe_repositories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_repositories"]
  audit_objects ["object.repositories.repository_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.repositories.repository_arn"]
end
  
coreo_aws_rule_runner "ecr-inventory-runner" do
  action :run
  service :ECR
  rules ["ecr-inventory-repositories"]
end
coreo_aws_rule "ecs-inventory-clusters" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Inventory"
  description "This rule performs an inventory on the ECS service using the describe_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_clusters"]
  audit_objects ["object.failures.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.failures.arn"]
end
coreo_aws_rule "ecs-inventory-clusters" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Inventory"
  description "This rule performs an inventory on the ECS service using the list_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_clusters"]
  audit_objects ["object.cluster_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cluster_arns"]
end
coreo_aws_rule "ecs-inventory-task_definition_families" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Inventory"
  description "This rule performs an inventory on the ECS service using the list_task_definition_families function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_task_definition_families"]
  audit_objects ["object.families"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.families"]
end
coreo_aws_rule "ecs-inventory-task_definitions" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Inventory"
  description "This rule performs an inventory on the ECS service using the list_task_definitions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_task_definitions"]
  audit_objects ["object.task_definition_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.task_definition_arns"]
end
  
coreo_aws_rule_runner "ecs-inventory-runner" do
  action :run
  service :ECS
  rules ["ecs-inventory-clusters", "ecs-inventory-clusters", "ecs-inventory-task_definition_families", "ecs-inventory-task_definitions"]
end
coreo_aws_rule "efs-inventory-file_systems" do
  service :EFS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EFS Inventory"
  description "This rule performs an inventory on the EFS service using the describe_file_systems function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_file_systems"]
  audit_objects ["object.file_systems.file_system_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.file_systems.file_system_id"]
end
  
coreo_aws_rule_runner "efs-inventory-runner" do
  action :run
  service :EFS
  rules ["efs-inventory-file_systems"]
end
coreo_aws_rule "emr-inventory-clusters" do
  service :EMR
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EMR Inventory"
  description "This rule performs an inventory on the EMR service using the list_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_clusters"]
  audit_objects ["object.clusters.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.clusters.id"]
end
coreo_aws_rule "emr-inventory-security_configurations" do
  service :EMR
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EMR Inventory"
  description "This rule performs an inventory on the EMR service using the list_security_configurations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_security_configurations"]
  audit_objects ["object.security_configurations.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.security_configurations.name"]
end
  
coreo_aws_rule_runner "emr-inventory-runner" do
  action :run
  service :EMR
  rules ["emr-inventory-clusters", "emr-inventory-security_configurations"]
end
coreo_aws_rule "elasticache-inventory-snapshots" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_snapshots"]
  audit_objects ["object.snapshots.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshots.topic_arn"]
end
coreo_aws_rule "elasticache-inventory-cache_clusters" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_cache_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cache_clusters"]
  audit_objects ["object.cache_clusters.notification_configuration.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cache_clusters.notification_configuration.topic_arn"]
end
coreo_aws_rule "elasticache-inventory-cache_engine_versions" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_cache_engine_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cache_engine_versions"]
  audit_objects ["object.cache_engine_versions.engine"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cache_engine_versions.engine"]
end
coreo_aws_rule "elasticache-inventory-cache_parameter_groups" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_cache_parameter_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cache_parameter_groups"]
  audit_objects ["object.cache_parameter_groups.cache_parameter_group_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cache_parameter_groups.cache_parameter_group_name"]
end
coreo_aws_rule "elasticache-inventory-cache_subnet_groups" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_cache_subnet_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cache_subnet_groups"]
  audit_objects ["object.cache_subnet_groups.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cache_subnet_groups.vpc_id"]
end
coreo_aws_rule "elasticache-inventory-events" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_events function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_events"]
  audit_objects ["object.events.source_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.events.source_identifier"]
end
coreo_aws_rule "elasticache-inventory-replication_groups" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_replication_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_replication_groups"]
  audit_objects ["object.replication_groups.replication_group_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.replication_groups.replication_group_id"]
end
coreo_aws_rule "elasticache-inventory-reserved_cache_nodes" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_reserved_cache_nodes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_cache_nodes"]
  audit_objects ["object.reserved_cache_nodes.reserved_cache_node_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_cache_nodes.reserved_cache_node_id"]
end
coreo_aws_rule "elasticache-inventory-reserved_cache_nodes_offerings" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_reserved_cache_nodes_offerings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_cache_nodes_offerings"]
  audit_objects ["object.reserved_cache_nodes_offerings.reserved_cache_nodes_offering_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_cache_nodes_offerings.reserved_cache_nodes_offering_id"]
end
  
coreo_aws_rule_runner "elasticache-inventory-runner" do
  action :run
  service :ElastiCache
  rules ["elasticache-inventory-snapshots", "elasticache-inventory-cache_clusters", "elasticache-inventory-cache_engine_versions", "elasticache-inventory-cache_parameter_groups", "elasticache-inventory-cache_subnet_groups", "elasticache-inventory-events", "elasticache-inventory-replication_groups", "elasticache-inventory-reserved_cache_nodes", "elasticache-inventory-reserved_cache_nodes_offerings"]
end
coreo_aws_rule "elasticbeanstalk-inventory-events" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the describe_events function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_events"]
  audit_objects ["object.events.platform_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.events.platform_arn"]
end
coreo_aws_rule "elasticbeanstalk-inventory-application_versions" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the describe_application_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_application_versions"]
  audit_objects ["object.application_versions.build_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.application_versions.build_arn"]
end
coreo_aws_rule "elasticbeanstalk-inventory-applications" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the describe_applications function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_applications"]
  audit_objects ["object.applications.application_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.applications.application_name"]
end
coreo_aws_rule "elasticbeanstalk-inventory-configuration_options" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the describe_configuration_options function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_configuration_options"]
  audit_objects ["object.platform_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.platform_arn"]
end
coreo_aws_rule "elasticbeanstalk-inventory-environments" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the describe_environments function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_environments"]
  audit_objects ["object.environments.platform_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.environments.platform_arn"]
end
coreo_aws_rule "elasticbeanstalk-inventory-available_solution_stacks" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the list_available_solution_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_available_solution_stacks"]
  audit_objects ["object.solution_stack_details.solution_stack_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.solution_stack_details.solution_stack_name"]
end
coreo_aws_rule "elasticbeanstalk-inventory-platform_versions" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the list_platform_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_platform_versions"]
  audit_objects ["object.platform_summary_list.platform_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.platform_summary_list.platform_arn"]
end
  
coreo_aws_rule_runner "elasticbeanstalk-inventory-runner" do
  action :run
  service :ElasticBeanstalk
  rules ["elasticbeanstalk-inventory-events", "elasticbeanstalk-inventory-application_versions", "elasticbeanstalk-inventory-applications", "elasticbeanstalk-inventory-configuration_options", "elasticbeanstalk-inventory-environments", "elasticbeanstalk-inventory-available_solution_stacks", "elasticbeanstalk-inventory-platform_versions"]
end
coreo_aws_rule "elasticloadbalancing-inventory-load_balancers" do
  service :ElasticLoadBalancing
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancing Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancing service using the describe_load_balancers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_load_balancers"]
  audit_objects ["object.load_balancer_descriptions.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.load_balancer_descriptions.vpc_id"]
end
coreo_aws_rule "elasticloadbalancing-inventory-load_balancer_policies" do
  service :ElasticLoadBalancing
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancing Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancing service using the describe_load_balancer_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_load_balancer_policies"]
  audit_objects ["object.policy_descriptions.policy_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.policy_descriptions.policy_name"]
end
coreo_aws_rule "elasticloadbalancing-inventory-load_balancer_policy_types" do
  service :ElasticLoadBalancing
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancing Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancing service using the describe_load_balancer_policy_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_load_balancer_policy_types"]
  audit_objects ["object.policy_type_descriptions.policy_type_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.policy_type_descriptions.policy_type_name"]
end
  
coreo_aws_rule_runner "elasticloadbalancing-inventory-runner" do
  action :run
  service :ElasticLoadBalancing
  rules ["elasticloadbalancing-inventory-load_balancers", "elasticloadbalancing-inventory-load_balancer_policies", "elasticloadbalancing-inventory-load_balancer_policy_types"]
end
coreo_aws_rule "elasticloadbalancingv2-inventory-load_balancers" do
  service :ElasticLoadBalancingV2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancingV2 Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancingV2 service using the describe_load_balancers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_load_balancers"]
  audit_objects ["object.load_balancers.load_balancer_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.load_balancers.load_balancer_arn"]
end
coreo_aws_rule "elasticloadbalancingv2-inventory-ssl_policies" do
  service :ElasticLoadBalancingV2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancingV2 Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancingV2 service using the describe_ssl_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_ssl_policies"]
  audit_objects ["object.ssl_policies.ssl_protocols"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ssl_policies.ssl_protocols"]
end
coreo_aws_rule "elasticloadbalancingv2-inventory-targroups" do
  service :ElasticLoadBalancingV2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancingV2 Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancingV2 service using the describe_target_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_target_groups"]
  audit_objects ["object.target_groups.target_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.target_groups.target_group_arn"]
end
  
coreo_aws_rule_runner "elasticloadbalancingv2-inventory-runner" do
  action :run
  service :ElasticLoadBalancingV2
  rules ["elasticloadbalancingv2-inventory-load_balancers", "elasticloadbalancingv2-inventory-ssl_policies", "elasticloadbalancingv2-inventory-targroups"]
end
coreo_aws_rule "elastictranscoder-inventory-pipelines" do
  service :ElasticTranscoder
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticTranscoder Inventory"
  description "This rule performs an inventory on the ElasticTranscoder service using the list_pipelines function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_pipelines"]
  audit_objects ["object.pipelines.aws_kms_key_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.pipelines.aws_kms_key_arn"]
end
coreo_aws_rule "elastictranscoder-inventory-presets" do
  service :ElasticTranscoder
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticTranscoder Inventory"
  description "This rule performs an inventory on the ElasticTranscoder service using the list_presets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_presets"]
  audit_objects ["object.presets.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.presets.arn"]
end
  
coreo_aws_rule_runner "elastictranscoder-inventory-runner" do
  action :run
  service :ElasticTranscoder
  rules ["elastictranscoder-inventory-pipelines", "elastictranscoder-inventory-presets"]
end
coreo_aws_rule "elasticsearchservice-inventory-domain_names" do
  service :ElasticsearchService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticsearchService Inventory"
  description "This rule performs an inventory on the ElasticsearchService service using the list_domain_names function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_domain_names"]
  audit_objects ["object.domain_names.domain_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.domain_names.domain_name"]
end
coreo_aws_rule "elasticsearchservice-inventory-elasticsearch_versions" do
  service :ElasticsearchService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticsearchService Inventory"
  description "This rule performs an inventory on the ElasticsearchService service using the list_elasticsearch_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_elasticsearch_versions"]
  audit_objects ["object.elasticsearch_versions"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.elasticsearch_versions"]
end
  
coreo_aws_rule_runner "elasticsearchservice-inventory-runner" do
  action :run
  service :ElasticsearchService
  rules ["elasticsearchservice-inventory-domain_names", "elasticsearchservice-inventory-elasticsearch_versions"]
end
coreo_aws_rule "firehose-inventory-delivery_streams" do
  service :Firehose
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Firehose Inventory"
  description "This rule performs an inventory on the Firehose service using the list_delivery_streams function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_delivery_streams"]
  audit_objects ["object.delivery_stream_names"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.delivery_stream_names"]
end
  
coreo_aws_rule_runner "firehose-inventory-runner" do
  action :run
  service :Firehose
  rules ["firehose-inventory-delivery_streams"]
end
coreo_aws_rule "gamelift-inventory-builds" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Inventory"
  description "This rule performs an inventory on the GameLift service using the list_builds function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_builds"]
  audit_objects ["object.builds.build_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.builds.build_id"]
end
coreo_aws_rule "gamelift-inventory-ec2_instance_limits" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Inventory"
  description "This rule performs an inventory on the GameLift service using the describe_ec2_instance_limits function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_ec2_instance_limits"]
  audit_objects ["object.ec2_instance_limits.ec2_instance_type"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ec2_instance_limits.ec2_instance_type"]
end
coreo_aws_rule "gamelift-inventory-fleet_attributes" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Inventory"
  description "This rule performs an inventory on the GameLift service using the describe_fleet_attributes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_fleet_attributes"]
  audit_objects ["object.fleet_attributes.fleet_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.fleet_attributes.fleet_arn"]
end
coreo_aws_rule "gamelift-inventory-game_session_queues" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Inventory"
  description "This rule performs an inventory on the GameLift service using the describe_game_session_queues function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_game_session_queues"]
  audit_objects ["object.game_session_queues.game_session_queue_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.game_session_queues.game_session_queue_arn"]
end
coreo_aws_rule "gamelift-inventory-aliases" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Inventory"
  description "This rule performs an inventory on the GameLift service using the list_aliases function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_aliases"]
  audit_objects ["object.aliases.alias_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.aliases.alias_arn"]
end
coreo_aws_rule "gamelift-inventory-fleets" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Inventory"
  description "This rule performs an inventory on the GameLift service using the list_fleets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_fleets"]
  audit_objects ["object.fleet_ids"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.fleet_ids"]
end
  
coreo_aws_rule_runner "gamelift-inventory-runner" do
  action :run
  service :GameLift
  rules ["gamelift-inventory-builds", "gamelift-inventory-ec2_instance_limits", "gamelift-inventory-fleet_attributes", "gamelift-inventory-game_session_queues", "gamelift-inventory-aliases", "gamelift-inventory-fleets"]
end
coreo_aws_rule "glacier-inventory-vaults" do
  service :Glacier
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Glacier Inventory"
  description "This rule performs an inventory on the Glacier service using the list_vaults function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_vaults"]
  audit_objects ["object.vault_list.vault_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vault_list.vault_arn"]
end
  
coreo_aws_rule_runner "glacier-inventory-runner" do
  action :run
  service :Glacier
  rules ["glacier-inventory-vaults"]
end
coreo_aws_rule "iam-inventory-account_authorization_details" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the get_account_authorization_details function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_account_authorization_details"]
  audit_objects ["object.user_detail_list.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.user_detail_list.arn"]
end
coreo_aws_rule "iam-inventory-access_keys" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_access_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_access_keys"]
  audit_objects ["object.access_key_metadata.access_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.access_key_metadata.access_key_id"]
end
coreo_aws_rule "iam-inventory-account_aliases" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_account_aliases function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_account_aliases"]
  audit_objects ["object.account_aliases"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.account_aliases"]
end
coreo_aws_rule "iam-inventory-groups" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_groups"]
  audit_objects ["object.groups.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.groups.arn"]
end
coreo_aws_rule "iam-inventory-instance_profiles" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_instance_profiles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_instance_profiles"]
  audit_objects ["object.instance_profiles.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instance_profiles.arn"]
end
coreo_aws_rule "iam-inventory-policies" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_policies"]
  audit_objects ["object.policies.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.policies.arn"]
end
coreo_aws_rule "iam-inventory-mfa_devices" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_mfa_devices function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_mfa_devices"]
  audit_objects ["object.mfa_devices.user_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.mfa_devices.user_name"]
end
coreo_aws_rule "iam-inventory-open_id_connect_providers" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_open_id_connect_providers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_open_id_connect_providers"]
  audit_objects ["object.open_id_connect_provider_list.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.open_id_connect_provider_list.arn"]
end
coreo_aws_rule "iam-inventory-saml_providers" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_saml_providers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_saml_providers"]
  audit_objects ["object.saml_provider_list.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.saml_provider_list.arn"]
end
coreo_aws_rule "iam-inventory-ssh_public_keys" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_ssh_public_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_ssh_public_keys"]
  audit_objects ["object.ssh_public_keys.ssh_public_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ssh_public_keys.ssh_public_key_id"]
end
coreo_aws_rule "iam-inventory-roles" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_roles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_roles"]
  audit_objects ["object.roles.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.roles.arn"]
end
coreo_aws_rule "iam-inventory-signing_certificates" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_signing_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_signing_certificates"]
  audit_objects ["object.certificates.certificate_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificates.certificate_id"]
end
coreo_aws_rule "iam-inventory-server_certificates" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_server_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_server_certificates"]
  audit_objects ["object.server_certificate_metadata_list.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.server_certificate_metadata_list.arn"]
end
coreo_aws_rule "iam-inventory-service_specific_credentials" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_service_specific_credentials function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_service_specific_credentials"]
  audit_objects ["object.service_specific_credentials.service_specific_credential_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.service_specific_credentials.service_specific_credential_id"]
end
coreo_aws_rule "iam-inventory-virtual_mfa_devices" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_virtual_mfa_devices function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_virtual_mfa_devices"]
  audit_objects ["object.virtual_mfa_devices.user.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.virtual_mfa_devices.user.arn"]
end
coreo_aws_rule "iam-inventory-users" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Inventory"
  description "This rule performs an inventory on the IAM service using the list_users function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_users"]
  audit_objects ["object.users.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.users.arn"]
end
  
coreo_aws_rule_runner "iam-inventory-runner" do
  action :run
  service :IAM
  rules ["iam-inventory-account_authorization_details", "iam-inventory-access_keys", "iam-inventory-account_aliases", "iam-inventory-groups", "iam-inventory-instance_profiles", "iam-inventory-policies", "iam-inventory-mfa_devices", "iam-inventory-open_id_connect_providers", "iam-inventory-saml_providers", "iam-inventory-ssh_public_keys", "iam-inventory-roles", "iam-inventory-signing_certificates", "iam-inventory-server_certificates", "iam-inventory-service_specific_credentials", "iam-inventory-virtual_mfa_devices", "iam-inventory-users"]
end
coreo_aws_rule "importexport-inventory-jobs" do
  service :ImportExport
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ImportExport Inventory"
  description "This rule performs an inventory on the ImportExport service using the list_jobs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_jobs"]
  audit_objects ["object.jobs.job_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.jobs.job_id"]
end
  
coreo_aws_rule_runner "importexport-inventory-runner" do
  action :run
  service :ImportExport
  rules ["importexport-inventory-jobs"]
end
coreo_aws_rule "inspector-inventory-assessment_runs" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Inventory"
  description "This rule performs an inventory on the Inspector service using the list_assessment_runs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_assessment_runs"]
  audit_objects ["object.assessment_run_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.assessment_run_arns"]
end
coreo_aws_rule "inspector-inventory-assessment_targets" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Inventory"
  description "This rule performs an inventory on the Inspector service using the list_assessment_targets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_assessment_targets"]
  audit_objects ["object.assessment_target_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.assessment_target_arns"]
end
coreo_aws_rule "inspector-inventory-assessment_templates" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Inventory"
  description "This rule performs an inventory on the Inspector service using the list_assessment_templates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_assessment_templates"]
  audit_objects ["object.assessment_template_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.assessment_template_arns"]
end
coreo_aws_rule "inspector-inventory-event_subscriptions" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Inventory"
  description "This rule performs an inventory on the Inspector service using the list_event_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_event_subscriptions"]
  audit_objects ["object.subscriptions.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.subscriptions.topic_arn"]
end
coreo_aws_rule "inspector-inventory-findings" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Inventory"
  description "This rule performs an inventory on the Inspector service using the list_findings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_findings"]
  audit_objects ["object.finding_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.finding_arns"]
end
coreo_aws_rule "inspector-inventory-rules_packages" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Inventory"
  description "This rule performs an inventory on the Inspector service using the list_rules_packages function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_rules_packages"]
  audit_objects ["object.rules_package_arns"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rules_package_arns"]
end
  
coreo_aws_rule_runner "inspector-inventory-runner" do
  action :run
  service :Inspector
  rules ["inspector-inventory-assessment_runs", "inspector-inventory-assessment_targets", "inspector-inventory-assessment_templates", "inspector-inventory-event_subscriptions", "inspector-inventory-findings", "inspector-inventory-rules_packages"]
end
coreo_aws_rule "iot-inventory-certificates" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_certificates"]
  audit_objects ["object.certificates.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificates.certificate_arn"]
end
coreo_aws_rule "iot-inventory-policies" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_policies"]
  audit_objects ["object.policies.policy_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.policies.policy_arn"]
end
coreo_aws_rule "iot-inventory-ca_certificates" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_ca_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_ca_certificates"]
  audit_objects ["object.certificates.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificates.certificate_arn"]
end
coreo_aws_rule "iot-inventory-outgoing_certificates" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_outgoing_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_outgoing_certificates"]
  audit_objects ["object.outgoing_certificates.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.outgoing_certificates.certificate_arn"]
end
coreo_aws_rule "iot-inventory-thing_types" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_thing_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_thing_types"]
  audit_objects ["object.thing_types.thing_type_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.thing_types.thing_type_name"]
end
coreo_aws_rule "iot-inventory-things" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_things function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_things"]
  audit_objects ["object.things.thing_type_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.things.thing_type_name"]
end
coreo_aws_rule "iot-inventory-topic_rules" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Inventory"
  description "This rule performs an inventory on the IoT service using the list_topic_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_topic_rules"]
  audit_objects ["object.rules.rule_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rules.rule_arn"]
end
  
coreo_aws_rule_runner "iot-inventory-runner" do
  action :run
  service :IoT
  rules ["iot-inventory-certificates", "iot-inventory-policies", "iot-inventory-ca_certificates", "iot-inventory-outgoing_certificates", "iot-inventory-thing_types", "iot-inventory-things", "iot-inventory-topic_rules"]
end
coreo_aws_rule "kms-inventory-aliases" do
  service :KMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KMS Inventory"
  description "This rule performs an inventory on the KMS service using the list_aliases function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_aliases"]
  audit_objects ["object.aliases.alias_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.aliases.alias_arn"]
end
coreo_aws_rule "kms-inventory-keys" do
  service :KMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KMS Inventory"
  description "This rule performs an inventory on the KMS service using the list_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_keys"]
  audit_objects ["object.keys.key_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.keys.key_arn"]
end
  
coreo_aws_rule_runner "kms-inventory-runner" do
  action :run
  service :KMS
  rules ["kms-inventory-aliases", "kms-inventory-keys"]
end
coreo_aws_rule "kinesis-inventory-streams" do
  service :Kinesis
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Kinesis Inventory"
  description "This rule performs an inventory on the Kinesis service using the list_streams function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_streams"]
  audit_objects ["object.stream_names"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.stream_names"]
end
  
coreo_aws_rule_runner "kinesis-inventory-runner" do
  action :run
  service :Kinesis
  rules ["kinesis-inventory-streams"]
end
coreo_aws_rule "kinesisanalytics-inventory-applications" do
  service :KinesisAnalytics
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KinesisAnalytics Inventory"
  description "This rule performs an inventory on the KinesisAnalytics service using the list_applications function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_applications"]
  audit_objects ["object.application_summaries.application_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.application_summaries.application_arn"]
end
  
coreo_aws_rule_runner "kinesisanalytics-inventory-runner" do
  action :run
  service :KinesisAnalytics
  rules ["kinesisanalytics-inventory-applications"]
end
coreo_aws_rule "lambda-inventory-event_source_mappings" do
  service :Lambda
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lambda Inventory"
  description "This rule performs an inventory on the Lambda service using the list_event_source_mappings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_event_source_mappings"]
  audit_objects ["object.event_source_mappings.function_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_source_mappings.function_arn"]
end
coreo_aws_rule "lambda-inventory-functions" do
  service :Lambda
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lambda Inventory"
  description "This rule performs an inventory on the Lambda service using the list_functions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_functions"]
  audit_objects ["object.functions.function_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.functions.function_arn"]
end
  
coreo_aws_rule_runner "lambda-inventory-runner" do
  action :run
  service :Lambda
  rules ["lambda-inventory-event_source_mappings", "lambda-inventory-functions"]
end
coreo_aws_rule "lambdapreview-inventory-functions" do
  service :LambdaPreview
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LambdaPreview Inventory"
  description "This rule performs an inventory on the LambdaPreview service using the list_functions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_functions"]
  audit_objects ["object.functions.function_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.functions.function_arn"]
end
coreo_aws_rule "lambdapreview-inventory-event_sources" do
  service :LambdaPreview
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LambdaPreview Inventory"
  description "This rule performs an inventory on the LambdaPreview service using the list_event_sources function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_event_sources"]
  audit_objects ["object.event_sources.function_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_sources.function_name"]
end
  
coreo_aws_rule_runner "lambdapreview-inventory-runner" do
  action :run
  service :LambdaPreview
  rules ["lambdapreview-inventory-functions", "lambdapreview-inventory-event_sources"]
end
coreo_aws_rule "lexmodelbuildingservice-inventory-bots" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Inventory"
  description "This rule performs an inventory on the LexModelBuildingService service using the get_bots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_bots"]
  audit_objects ["object.bots.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.bots.name"]
end
coreo_aws_rule "lexmodelbuildingservice-inventory-builtin_intents" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Inventory"
  description "This rule performs an inventory on the LexModelBuildingService service using the get_builtin_intents function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_builtin_intents"]
  audit_objects ["object.intents.signature"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.intents.signature"]
end
coreo_aws_rule "lexmodelbuildingservice-inventory-builtin_slot_types" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Inventory"
  description "This rule performs an inventory on the LexModelBuildingService service using the get_builtin_slot_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_builtin_slot_types"]
  audit_objects ["object.slot_types.signature"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.slot_types.signature"]
end
coreo_aws_rule "lexmodelbuildingservice-inventory-intents" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Inventory"
  description "This rule performs an inventory on the LexModelBuildingService service using the get_intents function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_intents"]
  audit_objects ["object.intents.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.intents.name"]
end
coreo_aws_rule "lexmodelbuildingservice-inventory-slot_types" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Inventory"
  description "This rule performs an inventory on the LexModelBuildingService service using the get_slot_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_slot_types"]
  audit_objects ["object.slot_types.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.slot_types.name"]
end
  
coreo_aws_rule_runner "lexmodelbuildingservice-inventory-runner" do
  action :run
  service :LexModelBuildingService
  rules ["lexmodelbuildingservice-inventory-bots", "lexmodelbuildingservice-inventory-builtin_intents", "lexmodelbuildingservice-inventory-builtin_slot_types", "lexmodelbuildingservice-inventory-intents", "lexmodelbuildingservice-inventory-slot_types"]
end
coreo_aws_rule "lightsail-inventory-regions" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_regions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_regions"]
  audit_objects ["object.regions.display_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.regions.display_name"]
end
coreo_aws_rule "lightsail-inventory-active_names" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_active_names function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_active_names"]
  audit_objects ["object.active_names"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.active_names"]
end
coreo_aws_rule "lightsail-inventory-blueprints" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_blueprints function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_blueprints"]
  audit_objects ["object.blueprints.blueprint_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.blueprints.blueprint_id"]
end
coreo_aws_rule "lightsail-inventory-bundles" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_bundles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_bundles"]
  audit_objects ["object.bundles.bundle_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.bundles.bundle_id"]
end
coreo_aws_rule "lightsail-inventory-domains" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_domains function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_domains"]
  audit_objects ["object.domains.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.domains.arn"]
end
coreo_aws_rule "lightsail-inventory-instance_snapshots" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_instance_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_instance_snapshots"]
  audit_objects ["object.instance_snapshots.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instance_snapshots.arn"]
end
coreo_aws_rule "lightsail-inventory-instances" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_instances"]
  audit_objects ["object.instances.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instances.arn"]
end
coreo_aws_rule "lightsail-inventory-key_pairs" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_key_pairs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_key_pairs"]
  audit_objects ["object.key_pairs.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.key_pairs.arn"]
end
coreo_aws_rule "lightsail-inventory-operations" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_operations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_operations"]
  audit_objects ["object.operations.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.operations.id"]
end
coreo_aws_rule "lightsail-inventory-static_ips" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_static_ips function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_static_ips"]
  audit_objects ["object.static_ips.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.static_ips.arn"]
end
  
coreo_aws_rule_runner "lightsail-inventory-runner" do
  action :run
  service :Lightsail
  rules ["lightsail-inventory-regions", "lightsail-inventory-active_names", "lightsail-inventory-blueprints", "lightsail-inventory-bundles", "lightsail-inventory-domains", "lightsail-inventory-instance_snapshots", "lightsail-inventory-instances", "lightsail-inventory-key_pairs", "lightsail-inventory-operations", "lightsail-inventory-static_ips"]
end
coreo_aws_rule "machinelearning-inventory-batch_predictions" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_batch_predictions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_batch_predictions"]
  audit_objects ["object.results.ml_model_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.ml_model_id"]
end
coreo_aws_rule "machinelearning-inventory-data_sources" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_data_sources function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_data_sources"]
  audit_objects ["object.results.role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.role_arn"]
end
coreo_aws_rule "machinelearning-inventory-evaluations" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_evaluations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_evaluations"]
  audit_objects ["object.results.ml_model_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.ml_model_id"]
end
coreo_aws_rule "machinelearning-inventory-ml_models" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_ml_models function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_ml_models"]
  audit_objects ["object.results.ml_model_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.ml_model_id"]
end
  
coreo_aws_rule_runner "machinelearning-inventory-runner" do
  action :run
  service :MachineLearning
  rules ["machinelearning-inventory-batch_predictions", "machinelearning-inventory-data_sources", "machinelearning-inventory-evaluations", "machinelearning-inventory-ml_models"]
end
coreo_aws_rule "opsworks-inventory-stacks" do
  service :OpsWorks
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorks Inventory"
  description "This rule performs an inventory on the OpsWorks service using the describe_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_stacks"]
  audit_objects ["object.stacks.service_role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.stacks.service_role_arn"]
end
coreo_aws_rule "opsworks-inventory-service_errors" do
  service :OpsWorks
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorks Inventory"
  description "This rule performs an inventory on the OpsWorks service using the describe_service_errors function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_service_errors"]
  audit_objects ["object.service_errors.stack_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.service_errors.stack_id"]
end
coreo_aws_rule "opsworks-inventory-user_profiles" do
  service :OpsWorks
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorks Inventory"
  description "This rule performs an inventory on the OpsWorks service using the describe_user_profiles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_user_profiles"]
  audit_objects ["object.user_profiles.iam_user_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.user_profiles.iam_user_arn"]
end
  
coreo_aws_rule_runner "opsworks-inventory-runner" do
  action :run
  service :OpsWorks
  rules ["opsworks-inventory-stacks", "opsworks-inventory-service_errors", "opsworks-inventory-user_profiles"]
end
coreo_aws_rule "opsworkscm-inventory-account_attributes" do
  service :OpsWorksCM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorksCM Inventory"
  description "This rule performs an inventory on the OpsWorksCM service using the describe_account_attributes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_account_attributes"]
  audit_objects ["object.attributes.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.attributes.name"]
end
coreo_aws_rule "opsworkscm-inventory-backups" do
  service :OpsWorksCM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorksCM Inventory"
  description "This rule performs an inventory on the OpsWorksCM service using the describe_backups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_backups"]
  audit_objects ["object.backups.user_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.backups.user_arn"]
end
coreo_aws_rule "opsworkscm-inventory-servers" do
  service :OpsWorksCM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorksCM Inventory"
  description "This rule performs an inventory on the OpsWorksCM service using the describe_servers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_servers"]
  audit_objects ["object.servers.cloud_formation_stack_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.servers.cloud_formation_stack_arn"]
end
  
coreo_aws_rule_runner "opsworkscm-inventory-runner" do
  action :run
  service :OpsWorksCM
  rules ["opsworkscm-inventory-account_attributes", "opsworkscm-inventory-backups", "opsworkscm-inventory-servers"]
end
coreo_aws_rule "polly-inventory-voices" do
  service :Polly
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Polly Inventory"
  description "This rule performs an inventory on the Polly service using the describe_voices function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_voices"]
  audit_objects ["object.voices.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.voices.id"]
end
coreo_aws_rule "polly-inventory-lexicons" do
  service :Polly
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Polly Inventory"
  description "This rule performs an inventory on the Polly service using the list_lexicons function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_lexicons"]
  audit_objects ["object.lexicons.attributes.lexicon_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.lexicons.attributes.lexicon_arn"]
end
  
coreo_aws_rule_runner "polly-inventory-runner" do
  action :run
  service :Polly
  rules ["polly-inventory-voices", "polly-inventory-lexicons"]
end
coreo_aws_rule "rds-inventory-events" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_events function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_events"]
  audit_objects ["object.events.source_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.events.source_arn"]
end
coreo_aws_rule "rds-inventory-certificates" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_certificates"]
  audit_objects ["object.certificates.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificates.certificate_arn"]
end
coreo_aws_rule "rds-inventory-account_attributes" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_account_attributes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_account_attributes"]
  audit_objects ["object.account_quotas.account_quota_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.account_quotas.account_quota_name"]
end
coreo_aws_rule "rds-inventory-db_clusters" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_clusters"]
  audit_objects ["object.db_clusters.db_cluster_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_clusters.db_cluster_arn"]
end
coreo_aws_rule "rds-inventory-db_engine_versions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_engine_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_engine_versions"]
  audit_objects ["object.db_engine_versions.default_character_set.character_set_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_engine_versions.default_character_set.character_set_name"]
end
coreo_aws_rule "rds-inventory-db_cluster_parameter_groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_cluster_parameter_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_cluster_parameter_groups"]
  audit_objects ["object.db_cluster_parameter_groups.db_cluster_parameter_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_cluster_parameter_groups.db_cluster_parameter_group_arn"]
end
coreo_aws_rule "rds-inventory-db_parameter_groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_parameter_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_parameter_groups"]
  audit_objects ["object.db_parameter_groups.db_parameter_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_parameter_groups.db_parameter_group_arn"]
end
coreo_aws_rule "rds-inventory-db_cluster_snapshots" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_cluster_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_cluster_snapshots"]
  audit_objects ["object.db_cluster_snapshots.source_db_cluster_snapshot_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_cluster_snapshots.source_db_cluster_snapshot_arn"]
end
coreo_aws_rule "rds-inventory-db_security_groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_security_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_security_groups"]
  audit_objects ["object.db_security_groups.db_security_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_security_groups.db_security_group_arn"]
end
coreo_aws_rule "rds-inventory-db_instances" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_instances"]
  audit_objects ["object.db_instances.tde_credential_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_instances.tde_credential_arn"]
end
coreo_aws_rule "rds-inventory-db_subnet_groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_subnet_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_subnet_groups"]
  audit_objects ["object.db_subnet_groups.db_subnet_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_subnet_groups.db_subnet_group_arn"]
end
coreo_aws_rule "rds-inventory-db_snapshots" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_snapshots"]
  audit_objects ["object.db_snapshots.db_snapshot_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_snapshots.db_snapshot_arn"]
end
coreo_aws_rule "rds-inventory-event_categories" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_event_categories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_categories"]
  audit_objects ["object.event_categories_map_list.source_type"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_categories_map_list.source_type"]
end
coreo_aws_rule "rds-inventory-event_subscriptions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_event_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_subscriptions"]
  audit_objects ["object.event_subscriptions_list.event_subscription_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_subscriptions_list.event_subscription_arn"]
end
coreo_aws_rule "rds-inventory-option_groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_option_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_option_groups"]
  audit_objects ["object.option_groups_list.option_group_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.option_groups_list.option_group_arn"]
end
coreo_aws_rule "rds-inventory-reserved_db_instances" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_reserved_db_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_db_instances"]
  audit_objects ["object.reserved_db_instances.reserved_db_instance_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_db_instances.reserved_db_instance_arn"]
end
coreo_aws_rule "rds-inventory-pending_maintenance_actions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_pending_maintenance_actions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_pending_maintenance_actions"]
  audit_objects ["object.pending_maintenance_actions.pending_maintenance_action_details"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.pending_maintenance_actions.pending_maintenance_action_details"]
end
coreo_aws_rule "rds-inventory-source_regions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_source_regions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_source_regions"]
  audit_objects ["object.source_regions.region_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.source_regions.region_name"]
end
coreo_aws_rule "rds-inventory-reserved_db_instances_offerings" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Inventory"
  description "This rule performs an inventory on the RDS service using the describe_reserved_db_instances_offerings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_db_instances_offerings"]
  audit_objects ["object.reserved_db_instances_offerings.reserved_db_instances_offering_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_db_instances_offerings.reserved_db_instances_offering_id"]
end
  
coreo_aws_rule_runner "rds-inventory-runner" do
  action :run
  service :RDS
  rules ["rds-inventory-events", "rds-inventory-certificates", "rds-inventory-account_attributes", "rds-inventory-db_clusters", "rds-inventory-db_engine_versions", "rds-inventory-db_cluster_parameter_groups", "rds-inventory-db_parameter_groups", "rds-inventory-db_cluster_snapshots", "rds-inventory-db_security_groups", "rds-inventory-db_instances", "rds-inventory-db_subnet_groups", "rds-inventory-db_snapshots", "rds-inventory-event_categories", "rds-inventory-event_subscriptions", "rds-inventory-option_groups", "rds-inventory-reserved_db_instances", "rds-inventory-pending_maintenance_actions", "rds-inventory-source_regions", "rds-inventory-reserved_db_instances_offerings"]
end
coreo_aws_rule "redshift-inventory-clusters" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_clusters"]
  audit_objects ["object.clusters.iam_roles.iam_role_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.clusters.iam_roles.iam_role_arn"]
end
coreo_aws_rule "redshift-inventory-events" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_events function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_events"]
  audit_objects ["object.events.event_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.events.event_id"]
end
coreo_aws_rule "redshift-inventory-event_categories" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_event_categories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_categories"]
  audit_objects ["object.event_categories_map_list.events.event_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_categories_map_list.events.event_id"]
end
coreo_aws_rule "redshift-inventory-event_subscriptions" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_event_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_subscriptions"]
  audit_objects ["object.event_subscriptions_list.sns_topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_subscriptions_list.sns_topic_arn"]
end
coreo_aws_rule "redshift-inventory-cluster_parameter_groups" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_cluster_parameter_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cluster_parameter_groups"]
  audit_objects ["object.parameter_groups.parameter_group_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.parameter_groups.parameter_group_name"]
end
coreo_aws_rule "redshift-inventory-cluster_snapshots" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_cluster_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cluster_snapshots"]
  audit_objects ["object.snapshots.kms_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshots.kms_key_id"]
end
coreo_aws_rule "redshift-inventory-cluster_subnet_groups" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_cluster_subnet_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cluster_subnet_groups"]
  audit_objects ["object.cluster_subnet_groups.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cluster_subnet_groups.vpc_id"]
end
coreo_aws_rule "redshift-inventory-cluster_versions" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_cluster_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cluster_versions"]
  audit_objects ["object.cluster_versions.cluster_version"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cluster_versions.cluster_version"]
end
coreo_aws_rule "redshift-inventory-hsm_client_certificates" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_hsm_client_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_hsm_client_certificates"]
  audit_objects ["object.hsm_client_certificates.hsm_client_certificate_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.hsm_client_certificates.hsm_client_certificate_identifier"]
end
coreo_aws_rule "redshift-inventory-hsm_configurations" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_hsm_configurations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_hsm_configurations"]
  audit_objects ["object.hsm_configurations.hsm_partition_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.hsm_configurations.hsm_partition_name"]
end
coreo_aws_rule "redshift-inventory-orderable_cluster_options" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_orderable_cluster_options function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_orderable_cluster_options"]
  audit_objects ["object.orderable_cluster_options.cluster_version"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.orderable_cluster_options.cluster_version"]
end
coreo_aws_rule "redshift-inventory-reserved_node_offerings" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_reserved_node_offerings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_node_offerings"]
  audit_objects ["object.reserved_node_offerings.reserved_node_offering_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_node_offerings.reserved_node_offering_id"]
end
coreo_aws_rule "redshift-inventory-reserved_nodes" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_reserved_nodes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_reserved_nodes"]
  audit_objects ["object.reserved_nodes.reserved_node_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reserved_nodes.reserved_node_id"]
end
coreo_aws_rule "redshift-inventory-snapshot_copy_grants" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_snapshot_copy_grants function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_snapshot_copy_grants"]
  audit_objects ["object.snapshot_copy_grants.kms_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshot_copy_grants.kms_key_id"]
end
  
coreo_aws_rule_runner "redshift-inventory-runner" do
  action :run
  service :Redshift
  rules ["redshift-inventory-clusters", "redshift-inventory-events", "redshift-inventory-event_categories", "redshift-inventory-event_subscriptions", "redshift-inventory-cluster_parameter_groups", "redshift-inventory-cluster_snapshots", "redshift-inventory-cluster_subnet_groups", "redshift-inventory-cluster_versions", "redshift-inventory-hsm_client_certificates", "redshift-inventory-hsm_configurations", "redshift-inventory-orderable_cluster_options", "redshift-inventory-reserved_node_offerings", "redshift-inventory-reserved_nodes", "redshift-inventory-snapshot_copy_grants"]
end
coreo_aws_rule "rekognition-inventory-collections" do
  service :Rekognition
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Rekognition Inventory"
  description "This rule performs an inventory on the Rekognition service using the list_collections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_collections"]
  audit_objects ["object.collection_ids"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.collection_ids"]
end
  
coreo_aws_rule_runner "rekognition-inventory-runner" do
  action :run
  service :Rekognition
  rules ["rekognition-inventory-collections"]
end
coreo_aws_rule "resourcegroupstaggingapi-inventory-tag_keys" do
  service :ResourceGroupsTaggingAPI
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ResourceGroupsTaggingAPI Inventory"
  description "This rule performs an inventory on the ResourceGroupsTaggingAPI service using the get_tag_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_tag_keys"]
  audit_objects ["object.tag_keys"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.tag_keys"]
end
  
coreo_aws_rule_runner "resourcegroupstaggingapi-inventory-runner" do
  action :run
  service :ResourceGroupsTaggingAPI
  rules ["resourcegroupstaggingapi-inventory-tag_keys"]
end
coreo_aws_rule "route53-inventory-checker_ip_ranges" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
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
coreo_aws_rule "route53-inventory-geo_locations" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
  description "This rule performs an inventory on the Route53 service using the list_geo_locations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_geo_locations"]
  audit_objects ["object.geo_location_details_list.subdivision_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.geo_location_details_list.subdivision_name"]
end
coreo_aws_rule "route53-inventory-health_checks" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
  description "This rule performs an inventory on the Route53 service using the list_health_checks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_health_checks"]
  audit_objects ["object.health_checks.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.health_checks.id"]
end
coreo_aws_rule "route53-inventory-hosted_zones" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
  description "This rule performs an inventory on the Route53 service using the list_hosted_zones function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_hosted_zones"]
  audit_objects ["object.hosted_zones.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.hosted_zones.id"]
end
coreo_aws_rule "route53-inventory-reusable_delegation_sets" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
  description "This rule performs an inventory on the Route53 service using the list_reusable_delegation_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_reusable_delegation_sets"]
  audit_objects ["object.delegation_sets.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.delegation_sets.id"]
end
coreo_aws_rule "route53-inventory-traffic_policies" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
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
coreo_aws_rule "route53-inventory-traffic_policy_instances" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Inventory"
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
  rules ["route53-inventory-checker_ip_ranges", "route53-inventory-geo_locations", "route53-inventory-health_checks", "route53-inventory-hosted_zones", "route53-inventory-reusable_delegation_sets", "route53-inventory-traffic_policies", "route53-inventory-traffic_policy_instances"]
end
coreo_aws_rule "route53domains-inventory-domains" do
  service :Route53Domains
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53Domains Inventory"
  description "This rule performs an inventory on the Route53Domains service using the list_domains function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_domains"]
  audit_objects ["object.domains.domain_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.domains.domain_name"]
end
coreo_aws_rule "route53domains-inventory-operations" do
  service :Route53Domains
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53Domains Inventory"
  description "This rule performs an inventory on the Route53Domains service using the list_operations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_operations"]
  audit_objects ["object.operations.operation_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.operations.operation_id"]
end
  
coreo_aws_rule_runner "route53domains-inventory-runner" do
  action :run
  service :Route53Domains
  rules ["route53domains-inventory-domains", "route53domains-inventory-operations"]
end
coreo_aws_rule "s3-inventory-buckets" do
  service :S3
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "S3 Inventory"
  description "This rule performs an inventory on the S3 service using the list_buckets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_buckets"]
  audit_objects ["object.owner.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.owner.id"]
end
  
coreo_aws_rule_runner "s3-inventory-runner" do
  action :run
  service :S3
  rules ["s3-inventory-buckets"]
end
coreo_aws_rule "ses-inventory-identities" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Inventory"
  description "This rule performs an inventory on the SES service using the list_identities function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_identities"]
  audit_objects ["object.identities"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.identities"]
end
coreo_aws_rule "ses-inventory-send_statistics" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Inventory"
  description "This rule performs an inventory on the SES service using the get_send_statistics function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_send_statistics"]
  audit_objects ["object.send_data_points.timestamp"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.send_data_points.timestamp"]
end
coreo_aws_rule "ses-inventory-configuration_sets" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Inventory"
  description "This rule performs an inventory on the SES service using the list_configuration_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_configuration_sets"]
  audit_objects ["object.configuration_sets.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.configuration_sets.name"]
end
coreo_aws_rule "ses-inventory-receipt_filters" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Inventory"
  description "This rule performs an inventory on the SES service using the list_receipt_filters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_receipt_filters"]
  audit_objects ["object.filters.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.filters.name"]
end
coreo_aws_rule "ses-inventory-receipt_rule_sets" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Inventory"
  description "This rule performs an inventory on the SES service using the list_receipt_rule_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_receipt_rule_sets"]
  audit_objects ["object.rule_sets.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rule_sets.name"]
end
coreo_aws_rule "ses-inventory-verified_email_addresses" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Inventory"
  description "This rule performs an inventory on the SES service using the list_verified_email_addresses function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_verified_email_addresses"]
  audit_objects ["object.verified_email_addresses"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.verified_email_addresses"]
end
  
coreo_aws_rule_runner "ses-inventory-runner" do
  action :run
  service :SES
  rules ["ses-inventory-identities", "ses-inventory-send_statistics", "ses-inventory-configuration_sets", "ses-inventory-receipt_filters", "ses-inventory-receipt_rule_sets", "ses-inventory-verified_email_addresses"]
end
coreo_aws_rule "sms-inventory-connectors" do
  service :SMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SMS Inventory"
  description "This rule performs an inventory on the SMS service using the get_connectors function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_connectors"]
  audit_objects ["object.connector_list.vm_manager_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.connector_list.vm_manager_id"]
end
coreo_aws_rule "sms-inventory-replication_jobs" do
  service :SMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SMS Inventory"
  description "This rule performs an inventory on the SMS service using the get_replication_jobs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_replication_jobs"]
  audit_objects ["object.replication_job_list.replication_job_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.replication_job_list.replication_job_id"]
end
coreo_aws_rule "sms-inventory-servers" do
  service :SMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SMS Inventory"
  description "This rule performs an inventory on the SMS service using the get_servers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_servers"]
  audit_objects ["object.server_list.server_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.server_list.server_id"]
end
  
coreo_aws_rule_runner "sms-inventory-runner" do
  action :run
  service :SMS
  rules ["sms-inventory-connectors", "sms-inventory-replication_jobs", "sms-inventory-servers"]
end
coreo_aws_rule "sns-inventory-platform_applications" do
  service :SNS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SNS Inventory"
  description "This rule performs an inventory on the SNS service using the list_platform_applications function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_platform_applications"]
  audit_objects ["object.platform_applications.platform_application_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.platform_applications.platform_application_arn"]
end
coreo_aws_rule "sns-inventory-subscriptions" do
  service :SNS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SNS Inventory"
  description "This rule performs an inventory on the SNS service using the list_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_subscriptions"]
  audit_objects ["object.subscriptions.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.subscriptions.topic_arn"]
end
coreo_aws_rule "sns-inventory-topics" do
  service :SNS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SNS Inventory"
  description "This rule performs an inventory on the SNS service using the list_topics function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_topics"]
  audit_objects ["object.topics.topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.topics.topic_arn"]
end
  
coreo_aws_rule_runner "sns-inventory-runner" do
  action :run
  service :SNS
  rules ["sns-inventory-platform_applications", "sns-inventory-subscriptions", "sns-inventory-topics"]
end
coreo_aws_rule "sqs-inventory-queues" do
  service :SQS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SQS Inventory"
  description "This rule performs an inventory on the SQS service using the list_queues function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_queues"]
  audit_objects ["object.queue_urls"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.queue_urls"]
end
  
coreo_aws_rule_runner "sqs-inventory-runner" do
  action :run
  service :SQS
  rules ["sqs-inventory-queues"]
end
coreo_aws_rule "ssm-inventory-maintenance_windows" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_maintenance_windows function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_maintenance_windows"]
  audit_objects ["object.window_identities.window_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.window_identities.window_id"]
end
coreo_aws_rule "ssm-inventory-parameters" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_parameters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_parameters"]
  audit_objects ["object.parameters.key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.parameters.key_id"]
end
coreo_aws_rule "ssm-inventory-patch_baselines" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_patch_baselines function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_patch_baselines"]
  audit_objects ["object.baseline_identities.baseline_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.baseline_identities.baseline_id"]
end
coreo_aws_rule "ssm-inventory-patch_groups" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_patch_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_patch_groups"]
  audit_objects ["object.mappings.baseline_identity.baseline_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.mappings.baseline_identity.baseline_id"]
end
coreo_aws_rule "ssm-inventory-associations" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the list_associations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_associations"]
  audit_objects ["object.associations.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.associations.instance_id"]
end
coreo_aws_rule "ssm-inventory-command_invocations" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the list_command_invocations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_command_invocations"]
  audit_objects ["object.command_invocations.notification_config.notification_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.command_invocations.notification_config.notification_arn"]
end
coreo_aws_rule "ssm-inventory-commands" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the list_commands function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_commands"]
  audit_objects ["object.commands.notification_config.notification_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.commands.notification_config.notification_arn"]
end
coreo_aws_rule "ssm-inventory-documents" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the list_documents function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_documents"]
  audit_objects ["object.document_identifiers.platform_types"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.document_identifiers.platform_types"]
end
coreo_aws_rule "ssm-inventory-activations" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_activations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_activations"]
  audit_objects ["object.activation_list.activation_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.activation_list.activation_id"]
end
coreo_aws_rule "ssm-inventory-automation_executions" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_automation_executions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_automation_executions"]
  audit_objects ["object.automation_execution_metadata_list.automation_execution_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.automation_execution_metadata_list.automation_execution_id"]
end
coreo_aws_rule "ssm-inventory-available_patches" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Inventory"
  description "This rule performs an inventory on the SSM service using the describe_available_patches function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_available_patches"]
  audit_objects ["object.patches.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.patches.id"]
end
  
coreo_aws_rule_runner "ssm-inventory-runner" do
  action :run
  service :SSM
  rules ["ssm-inventory-maintenance_windows", "ssm-inventory-parameters", "ssm-inventory-patch_baselines", "ssm-inventory-patch_groups", "ssm-inventory-associations", "ssm-inventory-command_invocations", "ssm-inventory-commands", "ssm-inventory-documents", "ssm-inventory-activations", "ssm-inventory-automation_executions", "ssm-inventory-available_patches"]
end
coreo_aws_rule "servicecatalog-inventory-accepted_portfolio_shares" do
  service :ServiceCatalog
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ServiceCatalog Inventory"
  description "This rule performs an inventory on the ServiceCatalog service using the list_accepted_portfolio_shares function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_accepted_portfolio_shares"]
  audit_objects ["object.portfolio_details.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.portfolio_details.arn"]
end
coreo_aws_rule "servicecatalog-inventory-portfolios" do
  service :ServiceCatalog
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ServiceCatalog Inventory"
  description "This rule performs an inventory on the ServiceCatalog service using the list_portfolios function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_portfolios"]
  audit_objects ["object.portfolio_details.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.portfolio_details.arn"]
end
  
coreo_aws_rule_runner "servicecatalog-inventory-runner" do
  action :run
  service :ServiceCatalog
  rules ["servicecatalog-inventory-accepted_portfolio_shares", "servicecatalog-inventory-portfolios"]
end
coreo_aws_rule "shield-inventory-attacks" do
  service :Shield
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Shield Inventory"
  description "This rule performs an inventory on the Shield service using the list_attacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_attacks"]
  audit_objects ["object.attack_summaries.resource_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.attack_summaries.resource_arn"]
end
  
coreo_aws_rule_runner "shield-inventory-runner" do
  action :run
  service :Shield
  rules ["shield-inventory-attacks"]
end
coreo_aws_rule "simpledb-inventory-domains" do
  service :SimpleDB
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SimpleDB Inventory"
  description "This rule performs an inventory on the SimpleDB service using the list_domains function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_domains"]
  audit_objects ["object.domain_names"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.domain_names"]
end
  
coreo_aws_rule_runner "simpledb-inventory-runner" do
  action :run
  service :SimpleDB
  rules ["simpledb-inventory-domains"]
end
coreo_aws_rule "snowball-inventory-addresses" do
  service :Snowball
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Snowball Inventory"
  description "This rule performs an inventory on the Snowball service using the describe_addresses function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_addresses"]
  audit_objects ["object.addresses.address_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.addresses.address_id"]
end
coreo_aws_rule "snowball-inventory-jobs" do
  service :Snowball
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Snowball Inventory"
  description "This rule performs an inventory on the Snowball service using the list_jobs function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_jobs"]
  audit_objects ["object.job_list_entries.job_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.job_list_entries.job_id"]
end
coreo_aws_rule "snowball-inventory-clusters" do
  service :Snowball
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Snowball Inventory"
  description "This rule performs an inventory on the Snowball service using the list_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_clusters"]
  audit_objects ["object.cluster_list_entries.cluster_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cluster_list_entries.cluster_id"]
end
  
coreo_aws_rule_runner "snowball-inventory-runner" do
  action :run
  service :Snowball
  rules ["snowball-inventory-addresses", "snowball-inventory-jobs", "snowball-inventory-clusters"]
end
coreo_aws_rule "states-inventory-activities" do
  service :States
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "States Inventory"
  description "This rule performs an inventory on the States service using the list_activities function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_activities"]
  audit_objects ["object.activities.activity_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.activities.activity_arn"]
end
coreo_aws_rule "states-inventory-state_machines" do
  service :States
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "States Inventory"
  description "This rule performs an inventory on the States service using the list_state_machines function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_state_machines"]
  audit_objects ["object.state_machines.state_machine_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.state_machines.state_machine_arn"]
end
  
coreo_aws_rule_runner "states-inventory-runner" do
  action :run
  service :States
  rules ["states-inventory-activities", "states-inventory-state_machines"]
end
coreo_aws_rule "storagegateway-inventory-tape_archives" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Inventory"
  description "This rule performs an inventory on the StorageGateway service using the describe_tape_archives function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_tape_archives"]
  audit_objects ["object.tape_archives.tape_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.tape_archives.tape_arn"]
end
coreo_aws_rule "storagegateway-inventory-file_shares" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Inventory"
  description "This rule performs an inventory on the StorageGateway service using the list_file_shares function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_file_shares"]
  audit_objects ["object.file_share_info_list.file_share_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.file_share_info_list.file_share_arn"]
end
coreo_aws_rule "storagegateway-inventory-gateways" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Inventory"
  description "This rule performs an inventory on the StorageGateway service using the list_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_gateways"]
  audit_objects ["object.gateways.gateway_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.gateways.gateway_arn"]
end
coreo_aws_rule "storagegateway-inventory-tapes" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Inventory"
  description "This rule performs an inventory on the StorageGateway service using the list_tapes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_tapes"]
  audit_objects ["object.tape_infos.gateway_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.tape_infos.gateway_arn"]
end
coreo_aws_rule "storagegateway-inventory-volumes" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Inventory"
  description "This rule performs an inventory on the StorageGateway service using the list_volumes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_volumes"]
  audit_objects ["object.gateway_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.gateway_arn"]
end
  
coreo_aws_rule_runner "storagegateway-inventory-runner" do
  action :run
  service :StorageGateway
  rules ["storagegateway-inventory-tape_archives", "storagegateway-inventory-file_shares", "storagegateway-inventory-gateways", "storagegateway-inventory-tapes", "storagegateway-inventory-volumes"]
end
coreo_aws_rule "waf-inventory-rules" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_rules"]
  audit_objects ["object.rules.rule_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rules.rule_id"]
end
coreo_aws_rule "waf-inventory-byte_match_sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_byte_match_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_byte_match_sets"]
  audit_objects ["object.byte_match_sets.byte_match_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.byte_match_sets.byte_match_set_id"]
end
coreo_aws_rule "waf-inventory-ip_sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_ip_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_ip_sets"]
  audit_objects ["object.ip_sets.ip_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ip_sets.ip_set_id"]
end
coreo_aws_rule "waf-inventory-size_constraint_sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_size_constraint_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_size_constraint_sets"]
  audit_objects ["object.size_constraint_sets.size_constraint_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.size_constraint_sets.size_constraint_set_id"]
end
coreo_aws_rule "waf-inventory-sql_injection_match_sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_sql_injection_match_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_sql_injection_match_sets"]
  audit_objects ["object.sql_injection_match_sets.sql_injection_match_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.sql_injection_match_sets.sql_injection_match_set_id"]
end
coreo_aws_rule "waf-inventory-web_acls" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_web_acls function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_web_acls"]
  audit_objects ["object.web_acls.web_acl_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.web_acls.web_acl_id"]
end
coreo_aws_rule "waf-inventory-xss_match_sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Inventory"
  description "This rule performs an inventory on the WAF service using the list_xss_match_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_xss_match_sets"]
  audit_objects ["object.xss_match_sets.xss_match_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.xss_match_sets.xss_match_set_id"]
end
  
coreo_aws_rule_runner "waf-inventory-runner" do
  action :run
  service :WAF
  rules ["waf-inventory-rules", "waf-inventory-byte_match_sets", "waf-inventory-ip_sets", "waf-inventory-size_constraint_sets", "waf-inventory-sql_injection_match_sets", "waf-inventory-web_acls", "waf-inventory-xss_match_sets"]
end
coreo_aws_rule "wafregional-inventory-rules" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_rules"]
  audit_objects ["object.rules.rule_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rules.rule_id"]
end
coreo_aws_rule "wafregional-inventory-byte_match_sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_byte_match_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_byte_match_sets"]
  audit_objects ["object.byte_match_sets.byte_match_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.byte_match_sets.byte_match_set_id"]
end
coreo_aws_rule "wafregional-inventory-ip_sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_ip_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_ip_sets"]
  audit_objects ["object.ip_sets.ip_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.ip_sets.ip_set_id"]
end
coreo_aws_rule "wafregional-inventory-size_constraint_sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_size_constraint_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_size_constraint_sets"]
  audit_objects ["object.size_constraint_sets.size_constraint_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.size_constraint_sets.size_constraint_set_id"]
end
coreo_aws_rule "wafregional-inventory-sql_injection_match_sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_sql_injection_match_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_sql_injection_match_sets"]
  audit_objects ["object.sql_injection_match_sets.sql_injection_match_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.sql_injection_match_sets.sql_injection_match_set_id"]
end
coreo_aws_rule "wafregional-inventory-web_acls" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_web_acls function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_web_acls"]
  audit_objects ["object.web_acls.web_acl_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.web_acls.web_acl_id"]
end
coreo_aws_rule "wafregional-inventory-xss_match_sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Inventory"
  description "This rule performs an inventory on the WAFRegional service using the list_xss_match_sets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_xss_match_sets"]
  audit_objects ["object.xss_match_sets.xss_match_set_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.xss_match_sets.xss_match_set_id"]
end
  
coreo_aws_rule_runner "wafregional-inventory-runner" do
  action :run
  service :WAFRegional
  rules ["wafregional-inventory-rules", "wafregional-inventory-byte_match_sets", "wafregional-inventory-ip_sets", "wafregional-inventory-size_constraint_sets", "wafregional-inventory-sql_injection_match_sets", "wafregional-inventory-web_acls", "wafregional-inventory-xss_match_sets"]
end
coreo_aws_rule "workspaces-inventory-workspace_bundles" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Inventory"
  description "This rule performs an inventory on the WorkSpaces service using the describe_workspace_bundles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_workspace_bundles"]
  audit_objects ["object.bundles.bundle_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.bundles.bundle_id"]
end
coreo_aws_rule "workspaces-inventory-workspace_directories" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Inventory"
  description "This rule performs an inventory on the WorkSpaces service using the describe_workspace_directories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_workspace_directories"]
  audit_objects ["object.directories.directory_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.directories.directory_id"]
end
coreo_aws_rule "workspaces-inventory-workspaces" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Inventory"
  description "This rule performs an inventory on the WorkSpaces service using the describe_workspaces function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_workspaces"]
  audit_objects ["object.workspaces.workspace_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.workspaces.workspace_id"]
end
coreo_aws_rule "workspaces-inventory-workspaces_connection_status" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Inventory"
  description "This rule performs an inventory on the WorkSpaces service using the describe_workspaces_connection_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_workspaces_connection_status"]
  audit_objects ["object.workspaces_connection_status.workspace_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.workspaces_connection_status.workspace_id"]
end
  
coreo_aws_rule_runner "workspaces-inventory-runner" do
  action :run
  service :WorkSpaces
  rules ["workspaces-inventory-workspace_bundles", "workspaces-inventory-workspace_directories", "workspaces-inventory-workspaces", "workspaces-inventory-workspaces_connection_status"]
end
