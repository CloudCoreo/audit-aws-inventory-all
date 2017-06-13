# ACM
#   - list_certificates({})
#     - id: certificate_summary_list.certificate_arn
# APIGateway
#   - get_api_keys({})
#     - id: warnings
#   - get_authorizers({})
#   - get_base_path_mappings({})
#   - get_client_certificates({})
#     - id: items.client_certificate_id
#   - get_deployments({})
#   - get_documentation_parts({})
#   - get_documentation_versions({})
#   - get_domain_names({})
#     - id: items.certificate_arn
#   - get_models({})
#   - get_request_validators({})
#   - get_resources({})
#   - get_rest_apis({})
#     - id: items.id
#   - get_sdk_types({})
#     - id: items.friendly_name
#   - get_stages({})
#   - get_usage_plan_keys({})
#   - get_usage_plans({})
#     - id: items.id
# AppStream
#   - describe_images({})
#     - id: images.arn
#   - describe_fleets({})
#     - id: fleets.display_name
#   - describe_sessions({})
#   - describe_stacks({})
#     - id: stacks.arn
#   - list_associated_fleets({})
#   - list_associated_stacks({})
# ApplicationAutoScaling
#   - describe_scalable_targets({})
#   - describe_scaling_activities({})
#   - describe_scaling_policies({})
# ApplicationDiscoveryService
#   - describe_export_tasks({})
#   - describe_agents({})
#   - describe_configurations({})
#   - describe_export_configurations({})
#   - list_configurations({})
#   - list_server_neighbors({})
# AutoScaling
#   - describe_scaling_activities <- SKIPPING due to @useless_methods
#   - attach_load_balancer_target_groups({})
#   - describe_account_limits({})
#     - id: NA
#   - describe_adjustment_types <- SKIPPING due to @useless_methods
#   - describe_auto_scaling_groups({})
#     - id: auto_scaling_groups.auto_scaling_group_name
#   - describe_auto_scaling_instances({})
#     - id: auto_scaling_instances.instance_id
#   - describe_auto_scaling_notification_types <- SKIPPING due to @useless_methods
#   - describe_launch_configurations({})
#     - id: launch_configurations.image_id
#   - describe_lifecycle_hook_types <- SKIPPING due to @useless_methods
#   - describe_lifecycle_hooks({})
#   - describe_load_balancer_target_groups({})
#   - describe_load_balancers({})
#   - describe_metric_collection_types <- SKIPPING due to @useless_methods
#   - describe_notification_configurations({})
#     - id: notification_configurations.topic_arn
#   - describe_policies({})
#     - id: scaling_policies.auto_scaling_group_name
#   - describe_scaling_process_types <- SKIPPING due to @useless_methods
#   - describe_scheduled_actions({})
#     - id: scheduled_update_group_actions.scheduled_action_arn
#   - describe_termination_policy_types <- SKIPPING due to @useless_methods
#   - detach_load_balancer_target_groups({})
# Batch
#   - describe_compute_environments({})
#     - id: compute_environments.compute_environment_arn
#   - describe_job_definitions({})
#     - id: job_definitions.job_definition_arn
#   - describe_job_queues({})
#     - id: job_queues.job_queue_arn
#   - describe_jobs({})
#   - list_jobs({})
# Budgets
#   - describe_budgets({})
# CloudDirectory
#   - list_object_attributes({})
#   - list_applied_schema_arns({})
#   - list_attached_indices({})
#   - list_development_schema_arns({})
#     - id: schema_arns
#   - list_directories({})
#     - id: directories.directory_arn
#   - list_facet_attributes({})
#   - list_facet_names({})
#   - list_object_parent_paths({})
#   - list_object_parents({})
#   - list_object_policies({})
#   - list_policy_attachments({})
#   - list_published_schema_arns({})
#     - id: schema_arns
# CloudFormation
#   - describe_stacks({})
#     - id: stacks.role_arn
#   - describe_account_limits <- SKIPPING due to @useless_methods
#   - describe_stack_events({})
#   - describe_stack_resources({})
#   - list_change_sets({})
#   - list_exports({})
#     - id: exports.exporting_stack_id
#   - list_imports({})
#   - list_stack_resources({})
#   - list_stacks({})
#     - id: stack_summaries.stack_id
# CloudFront
#   - list_cloud_front_origin_access_identities({})
#     - id: cloud_front_origin_access_identity_list.items.id
#   - list_distributions({})
#     - id: distribution_list.items.id
#   - list_invalidations({})
#   - list_streaming_distributions({})
#     - id: streaming_distribution_list.items.domain_name
# CloudHSM
#   - list_available_zones <- SKIPPING due to @useless_methods
#   - list_hapgs({})
#     - id: hapg_list
#   - list_hsms({})
#     - id: hsm_list
#   - list_luna_clients({})
#     - id: client_list
# CloudSearch
#   - describe_analysis_schemes({})
#   - describe_availability_options({})
#   - describe_domains({})
#     - id: domain_status_list.arn
#   - describe_expressions({})
#   - describe_index_fields({})
#   - describe_scaling_parameters({})
#   - describe_service_access_policies({})
#   - describe_suggesters({})
#   - list_domain_names({})
#     - id: NA
# CloudSearchDomain
# CloudTrail
#   - describe_trails({})
#     - id: trail_list.kms_key_id
#   - get_event_selectors({})
#   - get_trail_status({})
#   - list_public_keys <- SKIPPING due to @engine_bug_exclusions
# CloudWatch
#   - describe_alarms({})
#     - id: metric_alarms.alarm_arn
#   - get_metric_statistics({})
#   - list_metrics({})
#     - id: metrics.metric_name
# CloudWatchEvents
#   - list_rules({})
#     - id: rules.arn
#   - put_targets({})
#   - remove_targets({})
# CloudWatchLogs
#   - describe_export_tasks({})
#     - id: export_tasks.task_id
#   - describe_destinations({})
#     - id: destinations.destination_name
#   - describe_log_groups({})
#     - id: log_groups.arn
#   - describe_log_streams({})
#   - describe_metric_filters({})
#     - id: metric_filters.filter_name
#   - describe_subscription_filters({})
#   - get_log_events({})
# CodeBuild
#   - batch_get_builds({})
#   - batch_get_projects({})
#   - list_builds({})
#     - id: ids
#   - list_curated_environment_images <- SKIPPING due to @useless_methods
#   - list_projects({})
#     - id: projects
# CodeCommit
#   - batch_get_repositories({})
#   - get_differences({})
#   - get_repository_triggers({})
#   - list_branches({})
#   - list_repositories({})
#     - id: repositories.repository_id
# CodeDeploy
#   - batch_get_application_revisions({})
#   - batch_get_applications({})
#   - batch_get_deployment_groups({})
#   - batch_get_deployment_instances({})
#   - batch_get_deployments({})
#   - batch_get_on_premises_instances({})
#   - list_application_revisions({})
#   - list_applications({})
#     - id: applications
#   - list_deployment_configs <- SKIPPING due to @useless_methods
#   - list_deployment_groups({})
#   - list_deployment_instances({})
#   - list_deployments({})
#     - id: deployments
#   - list_on_premises_instances({})
#     - id: instance_names
# CodePipeline
#   - get_job_details({})
#   - get_third_party_job_details({})
#   - list_action_types <- SKIPPING due to @useless_methods
#   - list_pipelines({})
#     - id: pipelines.name
# CodeStar
#   - list_projects({})
#     - id: projects.project_arn
#   - list_resources({})
#   - list_team_members({})
#   - list_user_profiles({})
#     - id: user_profiles.user_arn
# CognitoIdentity
#   - get_identity_pool_roles({})
#   - list_identities({})
#   - list_identity_pools({})
# CognitoIdentityProvider
#   - admin_list_devices({})
#   - list_devices({})
#   - list_groups({})
#   - list_user_import_jobs({})
#   - list_user_pool_clients({})
#   - list_user_pools({})
#   - list_users({})
# CognitoSync
#   - get_bulk_publish_details({})
#   - get_cognito_events({})
#   - list_datasets({})
#   - list_records({})
# ConfigService
#   - describe_config_rule_evaluation_status({})
#     - id: config_rules_evaluation_status.config_rule_arn
#   - describe_config_rules({})
#     - id: config_rules.config_rule_name
#   - describe_configuration_recorder_status({})
#     - id: configuration_recorders_status.name
#   - describe_configuration_recorders({})
#     - id: configuration_recorders.role_arn
#   - describe_delivery_channel_status({})
#     - id: delivery_channels_status.name
#   - describe_delivery_channels({})
#     - id: delivery_channels.sns_topic_arn
#   - list_discovered_resources({})
# CostandUsageReportService
#   - describe_report_definitions({})
# DataPipeline
#   - list_pipelines({})
#     - id: pipeline_id_list.id
#   - describe_objects({})
#   - describe_pipelines({})
# DatabaseMigrationService
#   - describe_account_attributes <- SKIPPING due to @useless_methods
#   - describe_certificates({})
#     - id: certificates.certificate_arn
#   - describe_connections({})
#     - id: connections.replication_instance_arn
#   - describe_endpoint_types <- SKIPPING due to @useless_methods
#   - describe_endpoints({})
#     - id: endpoints.kms_key_id
#   - describe_orderable_replication_instances({})
#     - id: orderable_replication_instances.engine_version
#   - describe_refresh_schemas_status({})
#   - describe_replication_instances({})
#     - id: replication_instances.replication_instance_identifier
#   - describe_replication_subnet_groups({})
#     - id: replication_subnet_groups.vpc_id
#   - describe_replication_tasks({})
#     - id: replication_tasks.source_endpoint_arn
#   - describe_schemas({})
#   - describe_table_statistics({})
# DeviceFarm
#   - list_jobs({})
#   - list_projects({})
#   - list_devices({})
#   - get_account_settings({})
#   - get_offering_status({})
#   - list_artifacts({})
#   - list_device_pools({})
#   - list_network_profiles({})
#   - list_offering_promotions({})
#   - list_offering_transactions({})
#   - list_offerings <- SKIPPING due to @global_ignorables
#   - list_remote_access_sessions({})
#   - list_runs({})
#   - list_samples({})
#   - list_suites({})
#   - list_tests({})
#   - list_unique_problems({})
#   - list_uploads({})
# DirectConnect
#   - describe_connections({})
#     - id: connections.connection_id
#   - describe_hosted_connections({})
#   - describe_interconnects({})
#   - describe_lags({})
#     - id: lags.lag_name
#   - describe_locations <- SKIPPING due to @useless_methods
#   - describe_virtual_gateways({})
#     - id: virtual_gateways.virtual_gateway_id
#   - describe_virtual_interfaces({})
#     - id: virtual_interfaces.virtual_interface_id
# DirectoryService
#   - describe_snapshots({})
#     - id: snapshots.directory_id
#   - describe_conditional_forwarders({})
#   - describe_directories({})
#     - id: directory_descriptions.short_name
#   - describe_event_topics({})
#     - id: event_topics.topic_arn
#   - describe_trusts({})
#     - id: trusts.directory_id
#   - get_directory_limits({})
#     - id: NA
#   - get_snapshot_limits({})
#   - list_ip_routes({})
#   - list_schema_extensions({})
# DynamoDB
#   - describe_limits({})
#     - id: NA
#   - list_tables({})
#     - id: last_evaluated_table_name
# DynamoDBStreams
#   - get_records({})
#   - list_streams({})
#     - id: last_evaluated_stream_arn
# EC2
#   - describe_account_attributes <- SKIPPING due to @useless_methods
#   - describe_availability_zones <- SKIPPING due to @useless_methods
#   - describe_classic_link_instances({})
#     - id: instances.instance_id
#   - describe_conversion_tasks({})
#     - id: conversion_tasks.conversion_task_id
#   - describe_customer_gateways({})
#     - id: customer_gateways.customer_gateway_id
#   - describe_dhcp_options({})
#     - id: dhcp_options.dhcp_options_id
#   - describe_egress_only_internet_gateways({})
#     - id: egress_only_internet_gateways.egress_only_internet_gateway_id
#   - describe_export_tasks({})
#     - id: export_tasks.export_task_id
#   - describe_flow_logs({})
#     - id: flow_logs.deliver_logs_permission_arn
#   - describe_host_reservation_offerings <- SKIPPING due to @global_ignorables
#   - describe_host_reservations({})
#     - id: host_reservation_set.host_reservation_id
#   - describe_hosts({})
#     - id: hosts.host_id
#   - describe_iam_instance_profile_associations({})
#     - id: iam_instance_profile_associations.association_id
#   - describe_import_image_tasks({})
#     - id: import_image_tasks.import_task_id
#   - describe_import_snapshot_tasks({})
#     - id: import_snapshot_tasks.import_task_id
#   - describe_instance_status({})
#     - id: instance_statuses.instance_id
#   - describe_instances({})
#     - id: reservations.reservation_id
#   - describe_internet_gateways({})
#     - id: internet_gateways.internet_gateway_id
#   - describe_key_pairs({})
#     - id: key_pairs.key_name
#   - describe_moving_addresses({})
#     - id: moving_address_statuses.public_ip
#   - describe_nat_gateways({})
#     - id: nat_gateways.vpc_id
#   - describe_network_acls({})
#     - id: network_acls.network_acl_id
#   - describe_network_interfaces({})
#     - id: network_interfaces.network_interface_id
#   - describe_placement_groups({})
#     - id: placement_groups.group_name
#   - describe_prefix_lists({})
#     - id: prefix_lists.prefix_list_id
#   - describe_reserved_instances({})
#     - id: reserved_instances.reserved_instances_id
#   - describe_reserved_instances_listings({})
#   - describe_reserved_instances_modifications({})
#     - id: reserved_instances_modifications.reserved_instances_modification_id
#   - describe_reserved_instances_offerings <- SKIPPING due to @global_ignorables
#   - describe_route_tables({})
#     - id: route_tables.route_table_id
#   - describe_scheduled_instances({})
#     - id: scheduled_instance_set.scheduled_instance_id
#   - describe_security_group_references({})
#   - describe_security_groups({})
#     - id: security_groups.owner_id
#   - describe_spot_fleet_instances({})
#   - describe_spot_fleet_requests({})
#     - id: spot_fleet_request_configs.spot_fleet_request_id
#   - describe_spot_instance_requests({})
#     - id: spot_instance_requests.spot_instance_request_id
#   - describe_stale_security_groups({})
#   - describe_subnets({})
#     - id: subnets.subnet_id
#   - describe_volume_status({})
#     - id: volume_statuses.volume_id
#   - describe_volumes({})
#     - id: volumes.volume_id
#   - describe_volumes_modifications({})
#     - id: volumes_modifications.volume_id
#   - describe_vpc_endpoint_services({})
#     - id: service_names
#   - describe_vpc_endpoints({})
#     - id: vpc_endpoints.vpc_endpoint_id
#   - describe_vpc_peering_connections({})
#     - id: vpc_peering_connections.vpc_peering_connection_id
#   - describe_vpcs({})
#     - id: vpcs.vpc_id
#   - describe_vpn_connections({})
#     - id: vpn_connections.vpn_connection_id
#   - describe_vpn_gateways({})
#     - id: vpn_gateways.vpn_gateway_id
#   - describe_images <- SKIPPING due to @engine_bug_exclusions
#   - describe_snapshots <- SKIPPING due to @engine_bug_exclusions
#   - describe_addresses({})
#     - id: addresses.allocation_id
#   - describe_bundle_tasks({})
#     - id: bundle_tasks.bundle_id
#   - describe_regions({})
#     - id: regions.region_name
# ECR
#   - describe_images({})
#   - describe_repositories({})
#     - id: repositories.repository_arn
#   - list_images({})
# ECS
#   - describe_clusters({})
#     - id: clusters.cluster_arn
#   - describe_container_instances({})
#   - describe_services({})
#   - describe_tasks({})
#   - list_attributes({})
#   - list_clusters({})
#     - id: cluster_arns
#   - list_container_instances({})
#   - list_services({})
#   - list_task_definition_families({})
#     - id: families
#   - list_task_definitions({})
#     - id: task_definition_arns
#   - list_tasks({})
# EFS
#   - describe_file_systems({})
#     - id: file_systems.owner_id
#   - describe_mount_target_security_groups({})
#   - describe_mount_targets({})
#   - modify_mount_target_security_groups({})
# EMR
#   - list_clusters({})
#     - id: clusters.id
#   - describe_job_flows({})
#   - list_bootstrap_actions({})
#   - list_instance_fleets({})
#   - list_instance_groups({})
#   - list_instances({})
#   - list_security_configurations({})
#     - id: security_configurations.name
#   - list_steps({})
# ElastiCache
#   - describe_snapshots({})
#     - id: snapshots.topic_arn
#   - describe_cache_clusters({})
#     - id: cache_clusters.cache_cluster_id
#   - describe_cache_engine_versions({})
#     - id: cache_engine_versions.engine
#   - describe_cache_parameter_groups({})
#     - id: cache_parameter_groups.cache_parameter_group_name
#   - describe_cache_parameters({})
#   - describe_cache_security_groups({})
#   - describe_cache_subnet_groups({})
#     - id: cache_subnet_groups.vpc_id
#   - describe_engine_default_parameters({})
#   - describe_events({})
#     - id: events.source_identifier
#   - describe_replication_groups({})
#     - id: replication_groups.replication_group_id
#   - describe_reserved_cache_nodes({})
#     - id: reserved_cache_nodes.reserved_cache_node_id
#   - describe_reserved_cache_nodes_offerings <- SKIPPING due to @global_ignorables
#   - list_allowed_node_type_modifications({})
# ElasticBeanstalk
#   - describe_events({})
#     - id: events.platform_arn
#   - describe_application_versions({})
#     - id: application_versions.build_arn
#   - describe_applications({})
#     - id: applications.application_name
#   - describe_configuration_options({})
#     - id: platform_arn
#   - describe_configuration_settings({})
#   - describe_environment_managed_actions({})
#   - describe_environment_resources({})
#   - describe_environments({})
#     - id: environments.platform_arn
#   - list_available_solution_stacks({})
#     - id: solution_stacks
#   - list_platform_versions({})
#     - id: platform_summary_list.platform_arn
# ElasticLoadBalancing
#   - describe_load_balancers({})
#     - id: load_balancer_descriptions.load_balancer_name
#   - create_load_balancer_listeners({})
#   - delete_load_balancer_listeners({})
#   - describe_load_balancer_attributes({})
#   - describe_load_balancer_policies({})
#     - id: policy_descriptions.policy_name
#   - describe_load_balancer_policy_types({})
#     - id: policy_type_descriptions.policy_type_name
# ElasticLoadBalancingV2
#   - describe_load_balancers({})
#     - id: load_balancers.dns_name
#   - describe_load_balancer_attributes({})
#   - deregister_targets({})
#   - describe_listeners({})
#   - describe_rules({})
#   - describe_ssl_policies({})
#     - id: ssl_policies.ssl_protocols
#   - describe_target_group_attributes({})
#   - describe_target_groups({})
#     - id: target_groups.target_group_arn
#   - modify_target_group_attributes({})
#   - register_targets({})
# ElasticTranscoder
#   - list_pipelines({})
#     - id: pipelines.arn
#   - list_jobs_by_status({})
#   - list_presets({})
#     - id: presets.arn
# ElasticsearchService
#   - list_domain_names({})
#     - id: domain_names.domain_name
#   - describe_elasticsearch_domains({})
#   - describe_elasticsearch_instance_type_limits({})
#   - list_elasticsearch_instance_types({})
#   - list_elasticsearch_versions({})
#     - id: elasticsearch_versions
# Firehose
#   - list_delivery_streams({})
#     - id: delivery_stream_names
# GameLift
#   - describe_instances({})
#   - describe_scaling_policies({})
#   - list_builds({})
#     - id: builds.build_id
#   - describe_alias({})
#   - describe_ec2_instance_limits({})
#     - id: ec2_instance_limits.ec2_instance_type
#   - describe_fleet_attributes({})
#     - id: fleet_attributes.fleet_arn
#   - describe_fleet_events({})
#   - describe_fleet_port_settings({})
#   - describe_game_session_details({})
#   - describe_game_session_queues({})
#     - id: game_session_queues.game_session_queue_arn
#   - describe_game_sessions({})
#   - describe_player_sessions({})
#   - get_instance_access({})
#   - list_aliases({})
#     - id: aliases.alias_id
#   - list_fleets({})
#     - id: fleet_ids
# Glacier
#   - list_jobs({})
#   - get_vault_notifications({})
#   - list_multipart_uploads({})
#   - list_parts({})
#   - list_vaults({})
#     - id: vault_list.vault_arn
# Health
#   - describe_events({})
#   - describe_affected_entities({})
#   - describe_entity_aggregates({})
#   - describe_event_aggregates({})
#   - describe_event_details({})
#   - describe_event_types({})
# IAM
#   - get_account_authorization_details({})
#     - id: user_detail_list.path
#   - list_access_keys({})
#     - id: access_key_metadata.access_key_id
#   - list_account_aliases({})
#     - id: account_aliases
#   - list_attached_role_policies({})
#   - list_attached_user_policies({})
#   - list_attached_group_policies({})
#   - list_groups({})
#     - id: groups.arn
#   - list_instance_profiles({})
#     - id: instance_profiles.path
#   - list_group_policies({})
#   - list_policies({})
#     - id: policies.arn
#   - list_policy_versions({})
#   - list_mfa_devices({})
#     - id: mfa_devices.user_name
#   - list_open_id_connect_providers({})
#     - id: open_id_connect_provider_list.arn
#   - list_saml_providers({})
#     - id: saml_provider_list.arn
#   - list_ssh_public_keys({})
#     - id: ssh_public_keys.ssh_public_key_id
#   - list_role_policies({})
#   - list_roles({})
#     - id: roles.arn
#   - list_signing_certificates({})
#     - id: certificates.certificate_id
#   - list_user_policies({})
#   - list_server_certificates({})
#     - id: server_certificate_metadata_list.arn
#   - list_service_specific_credentials({})
#     - id: service_specific_credentials.service_specific_credential_id
#   - list_virtual_mfa_devices({})
#     - id: virtual_mfa_devices.serial_number
#   - list_users({})
#     - id: users.arn
# ImportExport
#   - list_jobs({})
#     - id: jobs.job_id
#   - get_status({})
# Inspector
#   - describe_assessment_runs({})
#   - describe_assessment_targets({})
#   - describe_assessment_templates({})
#   - describe_findings({})
#   - describe_resource_groups({})
#   - describe_rules_packages({})
#   - list_assessment_run_agents({})
#   - list_assessment_runs({})
#     - id: assessment_run_arns
#   - list_assessment_targets({})
#     - id: assessment_target_arns
#   - list_assessment_templates({})
#     - id: assessment_template_arns
#   - list_event_subscriptions({})
#     - id: subscriptions.resource_arn
#   - list_findings({})
#     - id: finding_arns
#   - list_rules_packages({})
#     - id: rules_package_arns
# IoT
#   - list_certificates({})
#     - id: certificates.certificate_arn
#   - list_policies({})
#     - id: policies.policy_arn
#   - list_policy_versions({})
#   - get_logging_options({})
#   - list_ca_certificates({})
#     - id: certificates.certificate_arn
#   - list_outgoing_certificates({})
#     - id: outgoing_certificates.certificate_arn
#   - list_policy_principals({})
#   - list_principal_policies({})
#   - list_principal_things({})
#   - list_thing_principals({})
#   - list_thing_types({})
#     - id: thing_types.thing_type_name
#   - list_things({})
#     - id: things.thing_name
#   - list_topic_rules({})
#     - id: rules.rule_arn
# IoTDataPlane
# KMS
#   - list_aliases({})
#     - id: aliases.alias_arn
#   - get_key_rotation_status({})
#   - list_grants({})
#   - list_key_policies({})
#   - list_keys({})
#     - id: keys.key_arn
#   - list_retirable_grants({})
# Kinesis
#   - describe_limits({})
#     - id: NA
#   - get_records({})
#   - list_streams({})
#     - id: stream_names
# KinesisAnalytics
#   - list_applications({})
#     - id: application_summaries.application_arn
# Lambda
#   - get_account_settings({})
#     - id: NA
#   - list_aliases({})
#   - get_alias({})
#   - list_event_source_mappings({})
#     - id: event_source_mappings.event_source_arn
#   - list_functions({})
#     - id: functions.function_arn
# LambdaPreview
#   - list_functions({})
#     - id: functions.function_arn
#   - list_event_sources({})
#     - id: event_sources.function_name
# Lex
# LexModelBuildingService
#   - get_bot_alias({})
#   - get_bot_aliases({})
#   - get_bot_channel_associations({})
#   - get_bot_versions({})
#   - get_bots({})
#     - id: bots.name
#   - get_builtin_intents({})
#     - id: intents.signature
#   - get_builtin_slot_types({})
#     - id: slot_types.signature
#   - get_intent_versions({})
#   - get_intents({})
#     - id: intents.name
#   - get_slot_type_versions({})
#   - get_slot_types({})
#     - id: slot_types.name
# Lightsail
#   - get_regions({})
#     - id: regions.display_name
#   - get_active_names({})
#     - id: active_names
#   - get_blueprints({})
#     - id: blueprints.blueprint_id
#   - get_bundles({})
#     - id: bundles.bundle_id
#   - get_domains({})
#     - id: domains.name
#   - get_instance_access_details({})
#   - get_instance_port_states({})
#   - get_instance_snapshots({})
#     - id: instance_snapshots.arn
#   - get_instances({})
#     - id: instances.arn
#   - get_key_pairs({})
#     - id: key_pairs.arn
#   - get_operations({})
#     - id: operations.resource_name
#   - get_static_ips({})
#     - id: static_ips.arn
# MTurk
#   - list_bonus_payments({})
#   - list_hits({})
#   - list_qualification_requests({})
#   - list_qualification_types({})
#   - list_reviewable_hits({})
#   - list_worker_blocks({})
# MachineLearning
#   - describe_batch_predictions({})
#     - id: results.batch_prediction_id
#   - describe_data_sources({})
#     - id: results.data_source_id
#   - describe_evaluations({})
#     - id: results.evaluation_id
#   - describe_ml_models({})
#     - id: results.ml_model_id
# MarketplaceCommerceAnalytics
# MarketplaceMetering
# OpsWorks
#   - describe_agent_versions({})
#   - describe_apps({})
#   - describe_commands({})
#   - describe_deployments({})
#   - describe_ecs_clusters({})
#   - describe_elastic_ips({})
#   - describe_layers({})
#   - describe_stacks({})
#     - id: stacks.stack_id
#   - describe_elastic_load_balancers({})
#   - describe_service_errors({})
#     - id: service_errors.service_error_id
#   - describe_permissions({})
#   - describe_raid_arrays({})
#   - describe_instances({})
#   - describe_user_profiles({})
#     - id: user_profiles.iam_user_arn
#   - describe_stack_provisioning_parameters({})
#   - describe_rds_db_instances({})
#   - describe_volumes({})
# OpsWorksCM
#   - describe_account_attributes({})
#     - id: attributes.name
#   - describe_events({})
#   - describe_backups({})
#     - id: backups.backup_arn
#   - describe_node_association_status({})
#   - describe_servers({})
#     - id: servers.cloud_formation_stack_arn
# Organizations
#   - list_policies({})
#   - describe_create_account_status({})
#   - list_accounts({})
#   - list_create_account_status({})
#   - list_parents({})
#   - list_roots({})
# Pinpoint
#   - get_application_settings({})
#   - get_campaign_activities({})
#   - get_campaign_versions({})
#   - get_campaigns({})
#   - get_import_jobs({})
#   - get_segment_import_jobs({})
#   - get_segment_versions({})
#   - get_segments({})
# Polly
#   - describe_voices({})
#     - id: voices.id
#   - list_lexicons({})
#     - id: lexicons.name
# RDS
#   - describe_engine_default_parameters({})
#   - describe_events({})
#     - id: events.source_arn
#   - describe_certificates({})
#     - id: certificates.certificate_arn
#   - describe_db_log_files({})
#   - describe_account_attributes({})
#     - id: account_quotas.account_quota_name
#   - describe_db_cluster_parameter_groups({})
#     - id: db_cluster_parameter_groups.db_cluster_parameter_group_arn
#   - describe_db_cluster_snapshots({})
#     - id: db_cluster_snapshots.db_cluster_snapshot_arn
#   - describe_db_cluster_parameters({})
#   - describe_db_engine_versions({})
#     - id: db_engine_versions.engine
#   - describe_db_clusters({})
#     - id: db_clusters.allocated_storage
#   - describe_db_cluster_snapshot_attributes({})
#   - describe_db_instances({})
#     - id: db_instances.db_name
#   - describe_db_parameter_groups({})
#     - id: db_parameter_groups.db_parameter_group_arn
#   - describe_db_parameters({})
#   - describe_db_security_groups({})
#     - id: db_security_groups.db_security_group_arn
#   - describe_db_snapshot_attributes({})
#   - describe_db_snapshots({})
#     - id: db_snapshots.tde_credential_arn
#   - describe_db_subnet_groups({})
#     - id: db_subnet_groups.db_subnet_group_arn
#   - describe_engine_default_cluster_parameters({})
#   - describe_event_categories({})
#     - id: event_categories_map_list.source_type
#   - describe_event_subscriptions({})
#     - id: event_subscriptions_list.sns_topic_arn
#   - describe_option_group_options({})
#   - describe_option_groups({})
#     - id: option_groups_list.option_group_name
#   - describe_orderable_db_instance_options({})
#   - describe_pending_maintenance_actions({})
#     - id: pending_maintenance_actions.resource_identifier
#   - describe_reserved_db_instances({})
#     - id: reserved_db_instances.reserved_db_instance_arn
#   - describe_reserved_db_instances_offerings <- SKIPPING due to @global_ignorables
#   - describe_source_regions({})
#     - id: source_regions.region_name
# Redshift
#   - describe_clusters({})
#     - id: clusters.cluster_identifier
#   - describe_events({})
#     - id: events.event_id
#   - describe_event_categories({})
#     - id: event_categories_map_list.source_type
#   - describe_event_subscriptions({})
#     - id: event_subscriptions_list.sns_topic_arn
#   - describe_cluster_parameter_groups({})
#     - id: parameter_groups.parameter_group_name
#   - describe_cluster_parameters({})
#   - describe_cluster_security_groups({})
#   - describe_cluster_snapshots({})
#     - id: snapshots.snapshot_identifier
#   - describe_cluster_subnet_groups({})
#     - id: cluster_subnet_groups.vpc_id
#   - describe_cluster_versions({})
#     - id: cluster_versions.cluster_version
#   - describe_default_cluster_parameters({})
#   - describe_hsm_client_certificates({})
#     - id: hsm_client_certificates.hsm_client_certificate_identifier
#   - describe_hsm_configurations({})
#     - id: hsm_configurations.hsm_partition_name
#   - describe_logging_status({})
#   - describe_orderable_cluster_options({})
#     - id: orderable_cluster_options.cluster_version
#   - describe_reserved_node_offerings <- SKIPPING due to @global_ignorables
#   - describe_reserved_nodes({})
#     - id: reserved_nodes.reserved_node_id
#   - describe_snapshot_copy_grants({})
#     - id: snapshot_copy_grants.kms_key_id
#   - describe_table_restore_status({})
#   - get_cluster_credentials({})
# Rekognition
#   - list_collections({})
#     - id: collection_ids
#   - list_faces({})
# ResourceGroupsTaggingAPI
#   - get_resources({})
#   - get_tag_keys({})
#     - id: tag_keys
#   - get_tag_values({})
# Route53
#   - get_checker_ip_ranges <- SKIPPING due to @engine_bug_exclusions
#   - get_health_check_status({})
#   - list_geo_locations <- SKIPPING due to @engine_bug_exclusions
#   - list_health_checks <- SKIPPING due to @engine_bug_exclusions
#   - list_hosted_zones <- SKIPPING due to @engine_bug_exclusions
#   - list_resource_record_sets({})
#   - list_reusable_delegation_sets({})
#     - id: delegation_sets.id
#   - list_traffic_policies({})
#     - id: traffic_policy_summaries.id
#   - list_traffic_policy_instances({})
#     - id: traffic_policy_instances.id
#   - list_traffic_policy_versions({})
#   - list_vpc_association_authorizations({})
# Route53Domains
#   - get_contact_reachability_status({})
#   - get_domain_suggestions({})
#   - list_domains({})
#     - id: domains.domain_name
#   - list_operations({})
#     - id: operations.operation_id
# S3
#   - list_multipart_uploads({})
#   - list_parts({})
#   - list_buckets({})
#     - id: bucket.bucket_name
#   - get_bucket_cors({})
#   - list_bucket_analytics_configurations({})
#   - list_bucket_inventory_configurations({})
#   - list_bucket_metrics_configurations({})
#   - list_object_versions({})
#   - list_objects({})
# SES
#   - list_identities({})
#     - id: identities
#   - get_identity_dkim_attributes({})
#   - get_identity_mail_from_domain_attributes({})
#   - get_identity_notification_attributes({})
#   - get_identity_policies({})
#   - get_identity_verification_attributes({})
#   - get_send_statistics({})
#     - id: send_data_points.timestamp
#   - list_configuration_sets({})
#     - id: configuration_sets.name
#   - list_identity_policies({})
#   - list_receipt_filters({})
#     - id: filters.name
#   - list_receipt_rule_sets({})
#     - id: rule_sets.name
#   - list_verified_email_addresses({})
#     - id: verified_email_addresses
# SMS
#   - get_connectors({})
#     - id: connector_list.connector_id
#   - get_replication_jobs({})
#     - id: replication_job_list.replication_job_id
#   - get_replication_runs({})
#   - get_servers({})
#     - id: server_list.server_id
# SNS
#   - get_endpoint_attributes({})
#   - get_platform_application_attributes({})
#   - get_sms_attributes({})
#     - id: NA
#   - get_subscription_attributes({})
#   - get_topic_attributes({})
#   - list_platform_applications({})
#     - id: platform_applications.platform_application_arn
#   - list_subscriptions({})
#     - id: subscriptions.subscription_arn
#   - list_topics({})
#     - id: topics.topic_arn
# SQS
#   - get_queue_attributes({})
#   - list_dead_letter_source_queues({})
#   - list_queues({})
#     - id: queue_urls
# SSM
#   - describe_activations({})
#     - id: activation_list.activation_id
#   - describe_automation_executions({})
#     - id: automation_execution_metadata_list.automation_execution_id
#   - describe_available_patches <- SKIPPING due to @engine_bug_exclusions
#   - describe_effective_instance_associations({})
#   - describe_instance_associations_status({})
#   - describe_instance_patch_states({})
#   - describe_instance_patches({})
#   - describe_maintenance_window_execution_task_invocations({})
#   - describe_maintenance_window_execution_tasks({})
#   - describe_maintenance_window_executions({})
#   - describe_maintenance_window_targets({})
#   - describe_maintenance_window_tasks({})
#   - describe_maintenance_windows({})
#     - id: window_identities.window_id
#   - describe_parameters({})
#     - id: parameters.key_id
#   - describe_patch_baselines <- SKIPPING due to @engine_bug_exclusions
#   - describe_patch_groups({})
#     - id: mappings.patch_group
#   - get_parameters({})
#   - list_associations({})
#     - id: associations.instance_id
#   - list_command_invocations({})
#     - id: command_invocations.command_id
#   - list_commands({})
#     - id: commands.command_id
#   - list_document_versions({})
#   - list_documents <- SKIPPING due to @engine_bug_exclusions
#   - list_inventory_entries({})
# STS
# SWF
#   - list_domains({})
#   - list_activity_types({})
#   - list_closed_workflow_executions({})
#   - list_open_workflow_executions({})
#   - list_workflow_types({})
# ServiceCatalog
#   - describe_provisioning_parameters({})
#   - list_accepted_portfolio_shares({})
#     - id: portfolio_details.id
#   - list_launch_paths({})
#   - list_portfolio_access({})
#   - list_portfolios({})
#     - id: portfolio_details.id
#   - list_provisioning_artifacts({})
# Shield
#   - list_attacks({})
#     - id: attack_summaries.resource_arn
#   - list_protections({})
# SimpleDB
#   - list_domains({})
#     - id: domain_names
#   - get_attributes({})
# Snowball
#   - describe_addresses({})
#     - id: addresses.address_id
#   - list_jobs({})
#     - id: job_list_entries.job_id
#   - list_clusters({})
#     - id: cluster_list_entries.cluster_id
#   - describe_address({})
#   - list_cluster_jobs({})
# States
#   - list_activities({})
#     - id: activities.activity_arn
#   - list_executions({})
#   - list_state_machines({})
#     - id: state_machines.state_machine_arn
# StorageGateway
#   - describe_cached_iscsi_volumes({})
#   - describe_chap_credentials({})
#   - describe_nfs_file_shares({})
#   - describe_stored_iscsi_volumes({})
#   - describe_tape_archives({})
#     - id: tape_archives.tape_arn
#   - describe_tape_recovery_points({})
#   - describe_tapes({})
#   - describe_vtl_devices({})
#   - list_file_shares({})
#     - id: file_share_info_list.file_share_arn
#   - list_gateways({})
#     - id: gateways.gateway_arn
#   - list_local_disks({})
#   - list_tapes({})
#     - id: tape_infos.tape_arn
#   - list_volume_initiators({})
#   - list_volume_recovery_points({})
#   - list_volumes({})
#     - id: gateway_arn
# Support
#   - describe_services({})
#   - describe_cases({})
#   - describe_communications({})
#   - describe_severity_levels({})
#   - describe_trusted_advisor_check_refresh_statuses({})
#   - describe_trusted_advisor_check_summaries({})
#   - describe_trusted_advisor_checks({})
# WAF
#   - list_rules({})
#     - id: rules.rule_id
#   - get_change_token_status({})
#   - get_sampled_requests({})
#   - list_byte_match_sets({})
#     - id: byte_match_sets.byte_match_set_id
#   - list_ip_sets({})
#     - id: ip_sets.ip_set_id
#   - list_size_constraint_sets({})
#     - id: size_constraint_sets.size_constraint_set_id
#   - list_sql_injection_match_sets({})
#     - id: sql_injection_match_sets.sql_injection_match_set_id
#   - list_web_acls({})
#     - id: web_acls.web_acl_id
#   - list_xss_match_sets({})
#     - id: xss_match_sets.xss_match_set_id
# WAFRegional
#   - list_rules({})
#     - id: rules.rule_id
#   - get_change_token_status({})
#   - get_sampled_requests({})
#   - list_byte_match_sets({})
#     - id: byte_match_sets.byte_match_set_id
#   - list_ip_sets({})
#     - id: ip_sets.ip_set_id
#   - list_size_constraint_sets({})
#     - id: size_constraint_sets.size_constraint_set_id
#   - list_sql_injection_match_sets({})
#     - id: sql_injection_match_sets.sql_injection_match_set_id
#   - list_web_acls({})
#     - id: web_acls.web_acl_id
#   - list_xss_match_sets({})
#     - id: xss_match_sets.xss_match_set_id
# WorkDocs
#   - describe_document_versions({})
#   - describe_folder_contents({})
#   - describe_notification_subscriptions({})
#   - describe_resource_permissions({})
#   - describe_users({})
# WorkSpaces
#   - describe_workspace_bundles({})
#     - id: bundles.bundle_id
#   - describe_workspace_directories({})
#     - id: directories.directory_name
#   - describe_workspaces({})
#     - id: workspaces.user_name
#   - describe_workspaces_connection_status({})
#     - id: workspaces_connection_status.workspace_id
# XRay
#   - batch_get_traces({})
#   - get_trace_summaries({})
coreo_aws_rule "acm-inventory-certificates" do
  service :ACM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ACM Certificates Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "apigateway-inventory-api-keys" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Api Keys Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_api_keys function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_api_keys"]
  audit_objects ["object.warnings"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.warnings"]
  
end
coreo_aws_rule "apigateway-inventory-client-certificates" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Client Certificates Inventory"
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
coreo_aws_rule "apigateway-inventory-domain-names" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Domain Names Inventory"
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
coreo_aws_rule "apigateway-inventory-rest-apis" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Rest Apis Inventory"
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
coreo_aws_rule "apigateway-inventory-sdk-types" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Sdk Types Inventory"
  description "This rule performs an inventory on the APIGateway service using the get_sdk_types function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_sdk_types"]
  audit_objects ["object.items.friendly_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.items.friendly_name"]
  
end
coreo_aws_rule "apigateway-inventory-usage-plans" do
  service :APIGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "APIGateway Usage Plans Inventory"
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
  rules ["apigateway-inventory-api-keys", "apigateway-inventory-client-certificates", "apigateway-inventory-domain-names", "apigateway-inventory-rest-apis", "apigateway-inventory-sdk-types", "apigateway-inventory-usage-plans"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "appstream-inventory-images" do
  service :AppStream
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AppStream Images Inventory"
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
  display_name "AppStream Fleets Inventory"
  description "This rule performs an inventory on the AppStream service using the describe_fleets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_fleets"]
  audit_objects ["object.fleets.display_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.fleets.display_name"]
  
end
coreo_aws_rule "appstream-inventory-stacks" do
  service :AppStream
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AppStream Stacks Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "autoscaling-inventory-auto-scaling-groups" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Auto Scaling Groups Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_auto_scaling_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_auto_scaling_groups"]
  audit_objects ["object.auto_scaling_groups.auto_scaling_group_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.auto_scaling_groups.auto_scaling_group_name"]
  
end
coreo_aws_rule "autoscaling-inventory-auto-scaling-instances" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Auto Scaling Instances Inventory"
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
coreo_aws_rule "autoscaling-inventory-launch-configurations" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Launch Configurations Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_launch_configurations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_launch_configurations"]
  audit_objects ["object.launch_configurations.image_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.launch_configurations.image_id"]
  
end
coreo_aws_rule "autoscaling-inventory-notification-configurations" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Notification Configurations Inventory"
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
  display_name "AutoScaling Policies Inventory"
  description "This rule performs an inventory on the AutoScaling service using the describe_policies function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_policies"]
  audit_objects ["object.scaling_policies.auto_scaling_group_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.scaling_policies.auto_scaling_group_name"]
  
end
coreo_aws_rule "autoscaling-inventory-scheduled-actions" do
  service :AutoScaling
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "AutoScaling Scheduled Actions Inventory"
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
  
coreo_aws_rule_runner "autoscaling-inventory-runner" do
  action :run
  service :AutoScaling
  rules ["autoscaling-inventory-auto-scaling-groups", "autoscaling-inventory-auto-scaling-instances", "autoscaling-inventory-launch-configurations", "autoscaling-inventory-notification-configurations", "autoscaling-inventory-policies", "autoscaling-inventory-scheduled-actions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "batch-inventory-compute-environments" do
  service :Batch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Batch Compute Environments Inventory"
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
coreo_aws_rule "batch-inventory-job-definitions" do
  service :Batch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Batch Job Definitions Inventory"
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
coreo_aws_rule "batch-inventory-job-queues" do
  service :Batch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Batch Job Queues Inventory"
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
  rules ["batch-inventory-compute-environments", "batch-inventory-job-definitions", "batch-inventory-job-queues"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "clouddirectory-inventory-development-schema-arns" do
  service :CloudDirectory
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudDirectory Development Schema Arns Inventory"
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
  display_name "CloudDirectory Directories Inventory"
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
coreo_aws_rule "clouddirectory-inventory-published-schema-arns" do
  service :CloudDirectory
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudDirectory Published Schema Arns Inventory"
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
  rules ["clouddirectory-inventory-development-schema-arns", "clouddirectory-inventory-directories", "clouddirectory-inventory-published-schema-arns"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudformation-inventory-stacks" do
  service :CloudFormation
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFormation Stacks Inventory"
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
coreo_aws_rule "cloudformation-inventory-exports" do
  service :CloudFormation
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFormation Exports Inventory"
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
  display_name "CloudFormation Stacks Inventory"
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
  rules ["cloudformation-inventory-stacks", "cloudformation-inventory-exports", "cloudformation-inventory-stacks"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudfront-inventory-cloud-front-origin-access-identities" do
  service :CloudFront
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFront Cloud Front Origin Access Identities Inventory"
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
  display_name "CloudFront Distributions Inventory"
  description "This rule performs an inventory on the CloudFront service using the list_distributions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_distributions"]
  audit_objects ["object.distribution_list.items.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.distribution_list.items.id"]
  
end
coreo_aws_rule "cloudfront-inventory-streaming-distributions" do
  service :CloudFront
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudFront Streaming Distributions Inventory"
  description "This rule performs an inventory on the CloudFront service using the list_streaming_distributions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_streaming_distributions"]
  audit_objects ["object.streaming_distribution_list.items.domain_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.streaming_distribution_list.items.domain_name"]
  
end
  
coreo_aws_rule_runner "cloudfront-inventory-runner" do
  action :run
  service :CloudFront
  rules ["cloudfront-inventory-cloud-front-origin-access-identities", "cloudfront-inventory-distributions", "cloudfront-inventory-streaming-distributions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudhsm-inventory-hapgs" do
  service :CloudHSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudHSM Hapgs Inventory"
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
  display_name "CloudHSM Hsms Inventory"
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
coreo_aws_rule "cloudhsm-inventory-luna-clients" do
  service :CloudHSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudHSM Luna Clients Inventory"
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
  rules ["cloudhsm-inventory-hapgs", "cloudhsm-inventory-hsms", "cloudhsm-inventory-luna-clients"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudsearch-inventory-domains" do
  service :CloudSearch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudSearch Domains Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudtrail-inventory-trails" do
  service :CloudTrail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudTrail Trails Inventory"
  description "This rule performs an inventory on the CloudTrail service using the describe_trails function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_trails"]
  audit_objects ["object.trail_list.kms_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.trail_list.kms_key_id"]
  
end
  
coreo_aws_rule_runner "cloudtrail-inventory-runner" do
  action :run
  service :CloudTrail
  rules ["cloudtrail-inventory-trails"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudwatch-inventory-alarms" do
  service :CloudWatch
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatch Alarms Inventory"
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
  display_name "CloudWatch Metrics Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudwatchevents-inventory-rules" do
  service :CloudWatchEvents
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchEvents Rules Inventory"
  description "This rule performs an inventory on the CloudWatchEvents service using the list_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_rules"]
  audit_objects ["object.rules.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.rules.arn"]
  
end
  
coreo_aws_rule_runner "cloudwatchevents-inventory-runner" do
  action :run
  service :CloudWatchEvents
  rules ["cloudwatchevents-inventory-rules"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "cloudwatchlogs-inventory-export-tasks" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Export Tasks Inventory"
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
  display_name "CloudWatchLogs Destinations Inventory"
  description "This rule performs an inventory on the CloudWatchLogs service using the describe_destinations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_destinations"]
  audit_objects ["object.destinations.destination_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.destinations.destination_name"]
  
end
coreo_aws_rule "cloudwatchlogs-inventory-log-groups" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Log Groups Inventory"
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
coreo_aws_rule "cloudwatchlogs-inventory-metric-filters" do
  service :CloudWatchLogs
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudWatchLogs Metric Filters Inventory"
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
  rules ["cloudwatchlogs-inventory-export-tasks", "cloudwatchlogs-inventory-destinations", "cloudwatchlogs-inventory-log-groups", "cloudwatchlogs-inventory-metric-filters"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "codebuild-inventory-builds" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Builds Inventory"
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
coreo_aws_rule "codebuild-inventory-projects" do
  service :CodeBuild
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeBuild Projects Inventory"
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
  rules ["codebuild-inventory-builds", "codebuild-inventory-projects"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "codecommit-inventory-repositories" do
  service :CodeCommit
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeCommit Repositories Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "codedeploy-inventory-applications" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy Applications Inventory"
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
coreo_aws_rule "codedeploy-inventory-deployments" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy Deployments Inventory"
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
coreo_aws_rule "codedeploy-inventory-on-premises-instances" do
  service :CodeDeploy
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeDeploy On Premises Instances Inventory"
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
  rules ["codedeploy-inventory-applications", "codedeploy-inventory-deployments", "codedeploy-inventory-on-premises-instances"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "codepipeline-inventory-pipelines" do
  service :CodePipeline
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodePipeline Pipelines Inventory"
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
  rules ["codepipeline-inventory-pipelines"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "codestar-inventory-projects" do
  service :CodeStar
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeStar Projects Inventory"
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
coreo_aws_rule "codestar-inventory-user-profiles" do
  service :CodeStar
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CodeStar User Profiles Inventory"
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
  rules ["codestar-inventory-projects", "codestar-inventory-user-profiles"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "configservice-inventory-config-rule-evaluation-status" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Config Rule Evaluation Status Inventory"
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
coreo_aws_rule "configservice-inventory-config-rules" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Config Rules Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_config_rules function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_config_rules"]
  audit_objects ["object.config_rules.config_rule_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.config_rules.config_rule_name"]
  
end
coreo_aws_rule "configservice-inventory-configuration-recorder-status" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Configuration Recorder Status Inventory"
  description "This rule performs an inventory on the ConfigService service using the describe_configuration_recorder_status function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_configuration_recorder_status"]
  audit_objects ["object.configuration_recorders_status.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.configuration_recorders_status.name"]
  
end
coreo_aws_rule "configservice-inventory-configuration-recorders" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Configuration Recorders Inventory"
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
coreo_aws_rule "configservice-inventory-delivery-channel-status" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Delivery Channel Status Inventory"
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
coreo_aws_rule "configservice-inventory-delivery-channels" do
  service :ConfigService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ConfigService Delivery Channels Inventory"
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
  rules ["configservice-inventory-config-rule-evaluation-status", "configservice-inventory-config-rules", "configservice-inventory-configuration-recorder-status", "configservice-inventory-configuration-recorders", "configservice-inventory-delivery-channel-status", "configservice-inventory-delivery-channels"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "datapipeline-inventory-pipelines" do
  service :DataPipeline
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DataPipeline Pipelines Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "databasemigrationservice-inventory-certificates" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Certificates Inventory"
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
  display_name "DatabaseMigrationService Connections Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_connections"]
  audit_objects ["object.connections.replication_instance_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.connections.replication_instance_arn"]
  
end
coreo_aws_rule "databasemigrationservice-inventory-endpoints" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Endpoints Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_endpoints function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_endpoints"]
  audit_objects ["object.endpoints.kms_key_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.endpoints.kms_key_id"]
  
end
coreo_aws_rule "databasemigrationservice-inventory-orderable-replication-instances" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Orderable Replication Instances Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_orderable_replication_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_orderable_replication_instances"]
  audit_objects ["object.orderable_replication_instances.engine_version"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.orderable_replication_instances.engine_version"]
  
end
coreo_aws_rule "databasemigrationservice-inventory-replication-instances" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Replication Instances Inventory"
  description "This rule performs an inventory on the DatabaseMigrationService service using the describe_replication_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_replication_instances"]
  audit_objects ["object.replication_instances.replication_instance_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.replication_instances.replication_instance_identifier"]
  
end
coreo_aws_rule "databasemigrationservice-inventory-replication-subnet-groups" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Replication Subnet Groups Inventory"
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
coreo_aws_rule "databasemigrationservice-inventory-replication-tasks" do
  service :DatabaseMigrationService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DatabaseMigrationService Replication Tasks Inventory"
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
  rules ["databasemigrationservice-inventory-certificates", "databasemigrationservice-inventory-connections", "databasemigrationservice-inventory-endpoints", "databasemigrationservice-inventory-orderable-replication-instances", "databasemigrationservice-inventory-replication-instances", "databasemigrationservice-inventory-replication-subnet-groups", "databasemigrationservice-inventory-replication-tasks"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "directconnect-inventory-connections" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Connections Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_connections"]
  audit_objects ["object.connections.connection_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.connections.connection_id"]
  
end
coreo_aws_rule "directconnect-inventory-lags" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Lags Inventory"
  description "This rule performs an inventory on the DirectConnect service using the describe_lags function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_lags"]
  audit_objects ["object.lags.lag_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.lags.lag_name"]
  
end
coreo_aws_rule "directconnect-inventory-virtual-gateways" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Virtual Gateways Inventory"
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
coreo_aws_rule "directconnect-inventory-virtual-interfaces" do
  service :DirectConnect
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectConnect Virtual Interfaces Inventory"
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
  rules ["directconnect-inventory-connections", "directconnect-inventory-lags", "directconnect-inventory-virtual-gateways", "directconnect-inventory-virtual-interfaces"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "directoryservice-inventory-snapshots" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Snapshots Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_snapshots"]
  audit_objects ["object.snapshots.directory_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshots.directory_id"]
  
end
coreo_aws_rule "directoryservice-inventory-directories" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Directories Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_directories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_directories"]
  audit_objects ["object.directory_descriptions.short_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.directory_descriptions.short_name"]
  
end
coreo_aws_rule "directoryservice-inventory-event-topics" do
  service :DirectoryService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DirectoryService Event Topics Inventory"
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
  display_name "DirectoryService Trusts Inventory"
  description "This rule performs an inventory on the DirectoryService service using the describe_trusts function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_trusts"]
  audit_objects ["object.trusts.directory_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.trusts.directory_id"]
  
end
  
coreo_aws_rule_runner "directoryservice-inventory-runner" do
  action :run
  service :DirectoryService
  rules ["directoryservice-inventory-snapshots", "directoryservice-inventory-directories", "directoryservice-inventory-event-topics", "directoryservice-inventory-trusts"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "dynamodb-inventory-tables" do
  service :DynamoDB
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DynamoDB Tables Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "dynamodbstreams-inventory-streams" do
  service :DynamoDBStreams
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "DynamoDBStreams Streams Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "ec2-inventory-classic-link-instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Classic Link Instances Inventory"
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
coreo_aws_rule "ec2-inventory-conversion-tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Conversion Tasks Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_conversion_tasks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_conversion_tasks"]
  audit_objects ["object.conversion_tasks.conversion_task_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.conversion_tasks.conversion_task_id"]
  
end
coreo_aws_rule "ec2-inventory-customer-gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Customer Gateways Inventory"
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
coreo_aws_rule "ec2-inventory-dhcp-options" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Dhcp Options Inventory"
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
coreo_aws_rule "ec2-inventory-egress-only-internet-gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Egress Only Internet Gateways Inventory"
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
coreo_aws_rule "ec2-inventory-export-tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Export Tasks Inventory"
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
coreo_aws_rule "ec2-inventory-flow-logs" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Flow Logs Inventory"
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
coreo_aws_rule "ec2-inventory-host-reservations" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Host Reservations Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_host_reservations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_host_reservations"]
  audit_objects ["object.host_reservation_set.host_reservation_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.host_reservation_set.host_reservation_id"]
  
end
coreo_aws_rule "ec2-inventory-hosts" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Hosts Inventory"
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
coreo_aws_rule "ec2-inventory-iam-instance-profile-associations" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Iam Instance Profile Associations Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_iam_instance_profile_associations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_iam_instance_profile_associations"]
  audit_objects ["object.iam_instance_profile_associations.association_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.iam_instance_profile_associations.association_id"]
  
end
coreo_aws_rule "ec2-inventory-import-image-tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Import Image Tasks Inventory"
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
coreo_aws_rule "ec2-inventory-import-snapshot-tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Import Snapshot Tasks Inventory"
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
coreo_aws_rule "ec2-inventory-instance-status" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Instance Status Inventory"
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
  display_name "EC2 Instances Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_instances"]
  audit_objects ["object.reservations.reservation_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.reservations.reservation_id"]
  
end
coreo_aws_rule "ec2-inventory-internet-gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Internet Gateways Inventory"
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
coreo_aws_rule "ec2-inventory-key-pairs" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Key Pairs Inventory"
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
coreo_aws_rule "ec2-inventory-moving-addresses" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Moving Addresses Inventory"
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
coreo_aws_rule "ec2-inventory-nat-gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Nat Gateways Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_nat_gateways function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_nat_gateways"]
  audit_objects ["object.nat_gateways.vpc_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.nat_gateways.vpc_id"]
  
end
coreo_aws_rule "ec2-inventory-network-acls" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Network Acls Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_network_acls function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_network_acls"]
  audit_objects ["object.network_acls.network_acl_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.network_acls.network_acl_id"]
  
end
coreo_aws_rule "ec2-inventory-network-interfaces" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Network Interfaces Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_network_interfaces function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_network_interfaces"]
  audit_objects ["object.network_interfaces.network_interface_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.network_interfaces.network_interface_id"]
  
end
coreo_aws_rule "ec2-inventory-placement-groups" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Placement Groups Inventory"
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
coreo_aws_rule "ec2-inventory-prefix-lists" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Prefix Lists Inventory"
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
coreo_aws_rule "ec2-inventory-reserved-instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Reserved Instances Inventory"
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
coreo_aws_rule "ec2-inventory-reserved-instances-modifications" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Reserved Instances Modifications Inventory"
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
coreo_aws_rule "ec2-inventory-route-tables" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Route Tables Inventory"
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
coreo_aws_rule "ec2-inventory-scheduled-instances" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Scheduled Instances Inventory"
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
coreo_aws_rule "ec2-inventory-security-groups" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Security Groups Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_security_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_security_groups"]
  audit_objects ["object.security_groups.owner_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.security_groups.owner_id"]
  
end
coreo_aws_rule "ec2-inventory-spot-fleet-requests" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Spot Fleet Requests Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_spot_fleet_requests function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_spot_fleet_requests"]
  audit_objects ["object.spot_fleet_request_configs.spot_fleet_request_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.spot_fleet_request_configs.spot_fleet_request_id"]
  
end
coreo_aws_rule "ec2-inventory-spot-instance-requests" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Spot Instance Requests Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_spot_instance_requests function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_spot_instance_requests"]
  audit_objects ["object.spot_instance_requests.spot_instance_request_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.spot_instance_requests.spot_instance_request_id"]
  
end
coreo_aws_rule "ec2-inventory-subnets" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Subnets Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_subnets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_subnets"]
  audit_objects ["object.subnets.subnet_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.subnets.subnet_id"]
  
end
coreo_aws_rule "ec2-inventory-volume-status" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Volume Status Inventory"
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
  display_name "EC2 Volumes Inventory"
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
coreo_aws_rule "ec2-inventory-volumes-modifications" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Volumes Modifications Inventory"
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
coreo_aws_rule "ec2-inventory-vpc-endpoint-services" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Vpc Endpoint Services Inventory"
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
coreo_aws_rule "ec2-inventory-vpc-endpoints" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Vpc Endpoints Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpc_endpoints function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpc_endpoints"]
  audit_objects ["object.vpc_endpoints.vpc_endpoint_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpc_endpoints.vpc_endpoint_id"]
  
end
coreo_aws_rule "ec2-inventory-vpc-peering-connections" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Vpc Peering Connections Inventory"
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
  display_name "EC2 Vpcs Inventory"
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
coreo_aws_rule "ec2-inventory-vpn-connections" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Vpn Connections Inventory"
  description "This rule performs an inventory on the EC2 service using the describe_vpn_connections function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_vpn_connections"]
  audit_objects ["object.vpn_connections.vpn_connection_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.vpn_connections.vpn_connection_id"]
  
end
coreo_aws_rule "ec2-inventory-vpn-gateways" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Vpn Gateways Inventory"
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
coreo_aws_rule "ec2-inventory-addresses" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Addresses Inventory"
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
coreo_aws_rule "ec2-inventory-bundle-tasks" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Bundle Tasks Inventory"
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
coreo_aws_rule "ec2-inventory-regions" do
  service :EC2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Regions Inventory"
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
  rules ["ec2-inventory-classic-link-instances", "ec2-inventory-conversion-tasks", "ec2-inventory-customer-gateways", "ec2-inventory-dhcp-options", "ec2-inventory-egress-only-internet-gateways", "ec2-inventory-export-tasks", "ec2-inventory-flow-logs", "ec2-inventory-host-reservations", "ec2-inventory-hosts", "ec2-inventory-iam-instance-profile-associations", "ec2-inventory-import-image-tasks", "ec2-inventory-import-snapshot-tasks", "ec2-inventory-instance-status", "ec2-inventory-instances", "ec2-inventory-internet-gateways", "ec2-inventory-key-pairs", "ec2-inventory-moving-addresses", "ec2-inventory-nat-gateways", "ec2-inventory-network-acls", "ec2-inventory-network-interfaces", "ec2-inventory-placement-groups", "ec2-inventory-prefix-lists", "ec2-inventory-reserved-instances", "ec2-inventory-reserved-instances-modifications", "ec2-inventory-route-tables", "ec2-inventory-scheduled-instances", "ec2-inventory-security-groups", "ec2-inventory-spot-fleet-requests", "ec2-inventory-spot-instance-requests", "ec2-inventory-subnets", "ec2-inventory-volume-status", "ec2-inventory-volumes", "ec2-inventory-volumes-modifications", "ec2-inventory-vpc-endpoint-services", "ec2-inventory-vpc-endpoints", "ec2-inventory-vpc-peering-connections", "ec2-inventory-vpcs", "ec2-inventory-vpn-connections", "ec2-inventory-vpn-gateways", "ec2-inventory-addresses", "ec2-inventory-bundle-tasks", "ec2-inventory-regions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "ecr-inventory-repositories" do
  service :ECR
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECR Repositories Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "ecs-inventory-clusters" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Clusters Inventory"
  description "This rule performs an inventory on the ECS service using the describe_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_clusters"]
  audit_objects ["object.clusters.cluster_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.clusters.cluster_arn"]
  
end
coreo_aws_rule "ecs-inventory-clusters" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Clusters Inventory"
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
coreo_aws_rule "ecs-inventory-task-definition-families" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Task Definition Families Inventory"
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
coreo_aws_rule "ecs-inventory-task-definitions" do
  service :ECS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ECS Task Definitions Inventory"
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
  rules ["ecs-inventory-clusters", "ecs-inventory-clusters", "ecs-inventory-task-definition-families", "ecs-inventory-task-definitions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "efs-inventory-file-systems" do
  service :EFS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EFS File Systems Inventory"
  description "This rule performs an inventory on the EFS service using the describe_file_systems function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_file_systems"]
  audit_objects ["object.file_systems.owner_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.file_systems.owner_id"]
  
end
  
coreo_aws_rule_runner "efs-inventory-runner" do
  action :run
  service :EFS
  rules ["efs-inventory-file-systems"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "emr-inventory-clusters" do
  service :EMR
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EMR Clusters Inventory"
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
coreo_aws_rule "emr-inventory-security-configurations" do
  service :EMR
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "EMR Security Configurations Inventory"
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
  rules ["emr-inventory-clusters", "emr-inventory-security-configurations"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "elasticache-inventory-snapshots" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Snapshots Inventory"
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
coreo_aws_rule "elasticache-inventory-cache-clusters" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Cache Clusters Inventory"
  description "This rule performs an inventory on the ElastiCache service using the describe_cache_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cache_clusters"]
  audit_objects ["object.cache_clusters.cache_cluster_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.cache_clusters.cache_cluster_id"]
  
end
coreo_aws_rule "elasticache-inventory-cache-engine-versions" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Cache Engine Versions Inventory"
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
coreo_aws_rule "elasticache-inventory-cache-parameter-groups" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Cache Parameter Groups Inventory"
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
coreo_aws_rule "elasticache-inventory-cache-subnet-groups" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Cache Subnet Groups Inventory"
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
  display_name "ElastiCache Events Inventory"
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
coreo_aws_rule "elasticache-inventory-replication-groups" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Replication Groups Inventory"
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
coreo_aws_rule "elasticache-inventory-reserved-cache-nodes" do
  service :ElastiCache
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElastiCache Reserved Cache Nodes Inventory"
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
  
coreo_aws_rule_runner "elasticache-inventory-runner" do
  action :run
  service :ElastiCache
  rules ["elasticache-inventory-snapshots", "elasticache-inventory-cache-clusters", "elasticache-inventory-cache-engine-versions", "elasticache-inventory-cache-parameter-groups", "elasticache-inventory-cache-subnet-groups", "elasticache-inventory-events", "elasticache-inventory-replication-groups", "elasticache-inventory-reserved-cache-nodes"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "elasticbeanstalk-inventory-events" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Events Inventory"
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
coreo_aws_rule "elasticbeanstalk-inventory-application-versions" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Application Versions Inventory"
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
  display_name "ElasticBeanstalk Applications Inventory"
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
coreo_aws_rule "elasticbeanstalk-inventory-configuration-options" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Configuration Options Inventory"
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
  display_name "ElasticBeanstalk Environments Inventory"
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
coreo_aws_rule "elasticbeanstalk-inventory-available-solution-stacks" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Available Solution Stacks Inventory"
  description "This rule performs an inventory on the ElasticBeanstalk service using the list_available_solution_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_available_solution_stacks"]
  audit_objects ["object.solution_stacks"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.solution_stacks"]
  
end
coreo_aws_rule "elasticbeanstalk-inventory-platform-versions" do
  service :ElasticBeanstalk
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticBeanstalk Platform Versions Inventory"
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
  rules ["elasticbeanstalk-inventory-events", "elasticbeanstalk-inventory-application-versions", "elasticbeanstalk-inventory-applications", "elasticbeanstalk-inventory-configuration-options", "elasticbeanstalk-inventory-environments", "elasticbeanstalk-inventory-available-solution-stacks", "elasticbeanstalk-inventory-platform-versions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "elasticloadbalancing-inventory-load-balancers" do
  service :ElasticLoadBalancing
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancing Load Balancers Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancing service using the describe_load_balancers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_load_balancers"]
  audit_objects ["object.load_balancer_descriptions.load_balancer_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.load_balancer_descriptions.load_balancer_name"]
  
end
coreo_aws_rule "elasticloadbalancing-inventory-load-balancer-policies" do
  service :ElasticLoadBalancing
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancing Load Balancer Policies Inventory"
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
coreo_aws_rule "elasticloadbalancing-inventory-load-balancer-policy-types" do
  service :ElasticLoadBalancing
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancing Load Balancer Policy Types Inventory"
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
  rules ["elasticloadbalancing-inventory-load-balancers", "elasticloadbalancing-inventory-load-balancer-policies", "elasticloadbalancing-inventory-load-balancer-policy-types"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "elasticloadbalancingv2-inventory-load-balancers" do
  service :ElasticLoadBalancingV2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancingV2 Load Balancers Inventory"
  description "This rule performs an inventory on the ElasticLoadBalancingV2 service using the describe_load_balancers function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_load_balancers"]
  audit_objects ["object.load_balancers.dns_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.load_balancers.dns_name"]
  
end
coreo_aws_rule "elasticloadbalancingv2-inventory-ssl-policies" do
  service :ElasticLoadBalancingV2
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticLoadBalancingV2 Ssl Policies Inventory"
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
  display_name "ElasticLoadBalancingV2 Targroups Inventory"
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
  rules ["elasticloadbalancingv2-inventory-load-balancers", "elasticloadbalancingv2-inventory-ssl-policies", "elasticloadbalancingv2-inventory-targroups"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "elastictranscoder-inventory-pipelines" do
  service :ElasticTranscoder
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticTranscoder Pipelines Inventory"
  description "This rule performs an inventory on the ElasticTranscoder service using the list_pipelines function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_pipelines"]
  audit_objects ["object.pipelines.arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.pipelines.arn"]
  
end
coreo_aws_rule "elastictranscoder-inventory-presets" do
  service :ElasticTranscoder
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticTranscoder Presets Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "elasticsearchservice-inventory-domain-names" do
  service :ElasticsearchService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticsearchService Domain Names Inventory"
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
coreo_aws_rule "elasticsearchservice-inventory-elasticsearch-versions" do
  service :ElasticsearchService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ElasticsearchService Elasticsearch Versions Inventory"
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
  rules ["elasticsearchservice-inventory-domain-names", "elasticsearchservice-inventory-elasticsearch-versions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "firehose-inventory-delivery-streams" do
  service :Firehose
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Firehose Delivery Streams Inventory"
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
  rules ["firehose-inventory-delivery-streams"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "gamelift-inventory-builds" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Builds Inventory"
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
coreo_aws_rule "gamelift-inventory-ec2-instance-limits" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Ec2 Instance Limits Inventory"
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
coreo_aws_rule "gamelift-inventory-fleet-attributes" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Fleet Attributes Inventory"
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
coreo_aws_rule "gamelift-inventory-game-session-queues" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Game Session Queues Inventory"
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
  display_name "GameLift Aliases Inventory"
  description "This rule performs an inventory on the GameLift service using the list_aliases function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_aliases"]
  audit_objects ["object.aliases.alias_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.aliases.alias_id"]
  
end
coreo_aws_rule "gamelift-inventory-fleets" do
  service :GameLift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "GameLift Fleets Inventory"
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
  rules ["gamelift-inventory-builds", "gamelift-inventory-ec2-instance-limits", "gamelift-inventory-fleet-attributes", "gamelift-inventory-game-session-queues", "gamelift-inventory-aliases", "gamelift-inventory-fleets"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "glacier-inventory-vaults" do
  service :Glacier
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Glacier Vaults Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "iam-inventory-account-authorization-details" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Account Authorization Details Inventory"
  description "This rule performs an inventory on the IAM service using the get_account_authorization_details function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_account_authorization_details"]
  audit_objects ["object.user_detail_list.path"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.user_detail_list.path"]
  
end
coreo_aws_rule "iam-inventory-access-keys" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Access Keys Inventory"
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
coreo_aws_rule "iam-inventory-account-aliases" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Account Aliases Inventory"
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
  display_name "IAM Groups Inventory"
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
coreo_aws_rule "iam-inventory-instance-profiles" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Instance Profiles Inventory"
  description "This rule performs an inventory on the IAM service using the list_instance_profiles function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_instance_profiles"]
  audit_objects ["object.instance_profiles.path"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.instance_profiles.path"]
  
end
coreo_aws_rule "iam-inventory-policies" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Policies Inventory"
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
coreo_aws_rule "iam-inventory-mfa-devices" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Mfa Devices Inventory"
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
coreo_aws_rule "iam-inventory-open-id-connect-providers" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Open Id Connect Providers Inventory"
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
coreo_aws_rule "iam-inventory-saml-providers" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Saml Providers Inventory"
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
coreo_aws_rule "iam-inventory-ssh-public-keys" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Ssh Public Keys Inventory"
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
  display_name "IAM Roles Inventory"
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
coreo_aws_rule "iam-inventory-signing-certificates" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Signing Certificates Inventory"
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
coreo_aws_rule "iam-inventory-server-certificates" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Server Certificates Inventory"
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
coreo_aws_rule "iam-inventory-service-specific-credentials" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Service Specific Credentials Inventory"
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
coreo_aws_rule "iam-inventory-virtual-mfa-devices" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Virtual Mfa Devices Inventory"
  description "This rule performs an inventory on the IAM service using the list_virtual_mfa_devices function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_virtual_mfa_devices"]
  audit_objects ["object.virtual_mfa_devices.serial_number"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.virtual_mfa_devices.serial_number"]
  
end
coreo_aws_rule "iam-inventory-users" do
  service :IAM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Users Inventory"
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
  rules ["iam-inventory-account-authorization-details", "iam-inventory-access-keys", "iam-inventory-account-aliases", "iam-inventory-groups", "iam-inventory-instance-profiles", "iam-inventory-policies", "iam-inventory-mfa-devices", "iam-inventory-open-id-connect-providers", "iam-inventory-saml-providers", "iam-inventory-ssh-public-keys", "iam-inventory-roles", "iam-inventory-signing-certificates", "iam-inventory-server-certificates", "iam-inventory-service-specific-credentials", "iam-inventory-virtual-mfa-devices", "iam-inventory-users"]
  
end
coreo_aws_rule "importexport-inventory-jobs" do
  service :ImportExport
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ImportExport Jobs Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "inspector-inventory-assessment-runs" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Assessment Runs Inventory"
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
coreo_aws_rule "inspector-inventory-assessment-targets" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Assessment Targets Inventory"
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
coreo_aws_rule "inspector-inventory-assessment-templates" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Assessment Templates Inventory"
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
coreo_aws_rule "inspector-inventory-event-subscriptions" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Event Subscriptions Inventory"
  description "This rule performs an inventory on the Inspector service using the list_event_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_event_subscriptions"]
  audit_objects ["object.subscriptions.resource_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.subscriptions.resource_arn"]
  
end
coreo_aws_rule "inspector-inventory-findings" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Findings Inventory"
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
coreo_aws_rule "inspector-inventory-rules-packages" do
  service :Inspector
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Inspector Rules Packages Inventory"
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
  rules ["inspector-inventory-assessment-runs", "inspector-inventory-assessment-targets", "inspector-inventory-assessment-templates", "inspector-inventory-event-subscriptions", "inspector-inventory-findings", "inspector-inventory-rules-packages"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "iot-inventory-certificates" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Certificates Inventory"
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
  display_name "IoT Policies Inventory"
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
coreo_aws_rule "iot-inventory-ca-certificates" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Ca Certificates Inventory"
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
coreo_aws_rule "iot-inventory-outgoing-certificates" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Outgoing Certificates Inventory"
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
coreo_aws_rule "iot-inventory-thing-types" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Thing Types Inventory"
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
  display_name "IoT Things Inventory"
  description "This rule performs an inventory on the IoT service using the list_things function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_things"]
  audit_objects ["object.things.thing_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.things.thing_name"]
  
end
coreo_aws_rule "iot-inventory-topic-rules" do
  service :IoT
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IoT Topic Rules Inventory"
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
  rules ["iot-inventory-certificates", "iot-inventory-policies", "iot-inventory-ca-certificates", "iot-inventory-outgoing-certificates", "iot-inventory-thing-types", "iot-inventory-things", "iot-inventory-topic-rules"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "kms-inventory-aliases" do
  service :KMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KMS Aliases Inventory"
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
  display_name "KMS Keys Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "kinesis-inventory-streams" do
  service :Kinesis
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Kinesis Streams Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "kinesisanalytics-inventory-applications" do
  service :KinesisAnalytics
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KinesisAnalytics Applications Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "lambda-inventory-event-source-mappings" do
  service :Lambda
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lambda Event Source Mappings Inventory"
  description "This rule performs an inventory on the Lambda service using the list_event_source_mappings function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_event_source_mappings"]
  audit_objects ["object.event_source_mappings.event_source_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_source_mappings.event_source_arn"]
  
end
coreo_aws_rule "lambda-inventory-functions" do
  service :Lambda
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lambda Functions Inventory"
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
  rules ["lambda-inventory-event-source-mappings", "lambda-inventory-functions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "lambdapreview-inventory-functions" do
  service :LambdaPreview
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LambdaPreview Functions Inventory"
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
coreo_aws_rule "lambdapreview-inventory-event-sources" do
  service :LambdaPreview
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LambdaPreview Event Sources Inventory"
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
  rules ["lambdapreview-inventory-functions", "lambdapreview-inventory-event-sources"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "lexmodelbuildingservice-inventory-bots" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Bots Inventory"
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
coreo_aws_rule "lexmodelbuildingservice-inventory-builtin-intents" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Builtin Intents Inventory"
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
coreo_aws_rule "lexmodelbuildingservice-inventory-builtin-slot-types" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Builtin Slot Types Inventory"
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
  display_name "LexModelBuildingService Intents Inventory"
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
coreo_aws_rule "lexmodelbuildingservice-inventory-slot-types" do
  service :LexModelBuildingService
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "LexModelBuildingService Slot Types Inventory"
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
  rules ["lexmodelbuildingservice-inventory-bots", "lexmodelbuildingservice-inventory-builtin-intents", "lexmodelbuildingservice-inventory-builtin-slot-types", "lexmodelbuildingservice-inventory-intents", "lexmodelbuildingservice-inventory-slot-types"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "lightsail-inventory-regions" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Regions Inventory"
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
coreo_aws_rule "lightsail-inventory-active-names" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Active Names Inventory"
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
  display_name "Lightsail Blueprints Inventory"
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
  display_name "Lightsail Bundles Inventory"
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
  display_name "Lightsail Domains Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_domains function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_domains"]
  audit_objects ["object.domains.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.domains.name"]
  
end
coreo_aws_rule "lightsail-inventory-instance-snapshots" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Instance Snapshots Inventory"
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
  display_name "Lightsail Instances Inventory"
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
coreo_aws_rule "lightsail-inventory-key-pairs" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Key Pairs Inventory"
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
  display_name "Lightsail Operations Inventory"
  description "This rule performs an inventory on the Lightsail service using the get_operations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_operations"]
  audit_objects ["object.operations.resource_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.operations.resource_name"]
  
end
coreo_aws_rule "lightsail-inventory-static-ips" do
  service :Lightsail
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Lightsail Static Ips Inventory"
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
  rules ["lightsail-inventory-regions", "lightsail-inventory-active-names", "lightsail-inventory-blueprints", "lightsail-inventory-bundles", "lightsail-inventory-domains", "lightsail-inventory-instance-snapshots", "lightsail-inventory-instances", "lightsail-inventory-key-pairs", "lightsail-inventory-operations", "lightsail-inventory-static-ips"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "machinelearning-inventory-batch-predictions" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Batch Predictions Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_batch_predictions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_batch_predictions"]
  audit_objects ["object.results.batch_prediction_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.batch_prediction_id"]
  
end
coreo_aws_rule "machinelearning-inventory-data-sources" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Data Sources Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_data_sources function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_data_sources"]
  audit_objects ["object.results.data_source_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.data_source_id"]
  
end
coreo_aws_rule "machinelearning-inventory-evaluations" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Evaluations Inventory"
  description "This rule performs an inventory on the MachineLearning service using the describe_evaluations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_evaluations"]
  audit_objects ["object.results.evaluation_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.results.evaluation_id"]
  
end
coreo_aws_rule "machinelearning-inventory-ml-models" do
  service :MachineLearning
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "MachineLearning Ml Models Inventory"
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
  rules ["machinelearning-inventory-batch-predictions", "machinelearning-inventory-data-sources", "machinelearning-inventory-evaluations", "machinelearning-inventory-ml-models"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "opsworks-inventory-stacks" do
  service :OpsWorks
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorks Stacks Inventory"
  description "This rule performs an inventory on the OpsWorks service using the describe_stacks function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_stacks"]
  audit_objects ["object.stacks.stack_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.stacks.stack_id"]
  
end
coreo_aws_rule "opsworks-inventory-service-errors" do
  service :OpsWorks
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorks Service Errors Inventory"
  description "This rule performs an inventory on the OpsWorks service using the describe_service_errors function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_service_errors"]
  audit_objects ["object.service_errors.service_error_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.service_errors.service_error_id"]
  
end
coreo_aws_rule "opsworks-inventory-user-profiles" do
  service :OpsWorks
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorks User Profiles Inventory"
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
  rules ["opsworks-inventory-stacks", "opsworks-inventory-service-errors", "opsworks-inventory-user-profiles"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "opsworkscm-inventory-account-attributes" do
  service :OpsWorksCM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorksCM Account Attributes Inventory"
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
  display_name "OpsWorksCM Backups Inventory"
  description "This rule performs an inventory on the OpsWorksCM service using the describe_backups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_backups"]
  audit_objects ["object.backups.backup_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.backups.backup_arn"]
  
end
coreo_aws_rule "opsworkscm-inventory-servers" do
  service :OpsWorksCM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "OpsWorksCM Servers Inventory"
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
  rules ["opsworkscm-inventory-account-attributes", "opsworkscm-inventory-backups", "opsworkscm-inventory-servers"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "polly-inventory-voices" do
  service :Polly
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Polly Voices Inventory"
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
  display_name "Polly Lexicons Inventory"
  description "This rule performs an inventory on the Polly service using the list_lexicons function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_lexicons"]
  audit_objects ["object.lexicons.name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.lexicons.name"]
  
end
  
coreo_aws_rule_runner "polly-inventory-runner" do
  action :run
  service :Polly
  rules ["polly-inventory-voices", "polly-inventory-lexicons"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "rds-inventory-events" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Events Inventory"
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
  display_name "RDS Certificates Inventory"
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
coreo_aws_rule "rds-inventory-account-attributes" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Account Attributes Inventory"
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
coreo_aws_rule "rds-inventory-db-cluster-parameter-groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Cluster Parameter Groups Inventory"
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
coreo_aws_rule "rds-inventory-db-cluster-snapshots" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Cluster Snapshots Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_cluster_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_cluster_snapshots"]
  audit_objects ["object.db_cluster_snapshots.db_cluster_snapshot_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_cluster_snapshots.db_cluster_snapshot_arn"]
  
end
coreo_aws_rule "rds-inventory-db-engine-versions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Engine Versions Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_engine_versions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_engine_versions"]
  audit_objects ["object.db_engine_versions.engine"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_engine_versions.engine"]
  
end
coreo_aws_rule "rds-inventory-db-clusters" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Clusters Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_clusters"]
  audit_objects ["object.db_clusters.allocated_storage"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_clusters.allocated_storage"]
  
end
coreo_aws_rule "rds-inventory-db-instances" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Instances Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_instances function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_instances"]
  audit_objects ["object.db_instances.db_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_instances.db_name"]
  
end
coreo_aws_rule "rds-inventory-db-parameter-groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Parameter Groups Inventory"
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
coreo_aws_rule "rds-inventory-db-security-groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Security Groups Inventory"
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
coreo_aws_rule "rds-inventory-db-snapshots" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Snapshots Inventory"
  description "This rule performs an inventory on the RDS service using the describe_db_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_db_snapshots"]
  audit_objects ["object.db_snapshots.tde_credential_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.db_snapshots.tde_credential_arn"]
  
end
coreo_aws_rule "rds-inventory-db-subnet-groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Db Subnet Groups Inventory"
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
coreo_aws_rule "rds-inventory-event-categories" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Event Categories Inventory"
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
coreo_aws_rule "rds-inventory-event-subscriptions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Event Subscriptions Inventory"
  description "This rule performs an inventory on the RDS service using the describe_event_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_subscriptions"]
  audit_objects ["object.event_subscriptions_list.sns_topic_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_subscriptions_list.sns_topic_arn"]
  
end
coreo_aws_rule "rds-inventory-option-groups" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Option Groups Inventory"
  description "This rule performs an inventory on the RDS service using the describe_option_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_option_groups"]
  audit_objects ["object.option_groups_list.option_group_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.option_groups_list.option_group_name"]
  
end
coreo_aws_rule "rds-inventory-pending-maintenance-actions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Pending Maintenance Actions Inventory"
  description "This rule performs an inventory on the RDS service using the describe_pending_maintenance_actions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_pending_maintenance_actions"]
  audit_objects ["object.pending_maintenance_actions.resource_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.pending_maintenance_actions.resource_identifier"]
  
end
coreo_aws_rule "rds-inventory-reserved-db-instances" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Reserved Db Instances Inventory"
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
coreo_aws_rule "rds-inventory-source-regions" do
  service :RDS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Source Regions Inventory"
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
  
coreo_aws_rule_runner "rds-inventory-runner" do
  action :run
  service :RDS
  rules ["rds-inventory-events", "rds-inventory-certificates", "rds-inventory-account-attributes", "rds-inventory-db-cluster-parameter-groups", "rds-inventory-db-cluster-snapshots", "rds-inventory-db-engine-versions", "rds-inventory-db-clusters", "rds-inventory-db-instances", "rds-inventory-db-parameter-groups", "rds-inventory-db-security-groups", "rds-inventory-db-snapshots", "rds-inventory-db-subnet-groups", "rds-inventory-event-categories", "rds-inventory-event-subscriptions", "rds-inventory-option-groups", "rds-inventory-pending-maintenance-actions", "rds-inventory-reserved-db-instances", "rds-inventory-source-regions"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "redshift-inventory-clusters" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Clusters Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_clusters function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_clusters"]
  audit_objects ["object.clusters.cluster_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.clusters.cluster_identifier"]
  
end
coreo_aws_rule "redshift-inventory-events" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Events Inventory"
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
coreo_aws_rule "redshift-inventory-event-categories" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Event Categories Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_event_categories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_event_categories"]
  audit_objects ["object.event_categories_map_list.source_type"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.event_categories_map_list.source_type"]
  
end
coreo_aws_rule "redshift-inventory-event-subscriptions" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Event Subscriptions Inventory"
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
coreo_aws_rule "redshift-inventory-cluster-parameter-groups" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Cluster Parameter Groups Inventory"
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
coreo_aws_rule "redshift-inventory-cluster-snapshots" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Cluster Snapshots Inventory"
  description "This rule performs an inventory on the Redshift service using the describe_cluster_snapshots function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_cluster_snapshots"]
  audit_objects ["object.snapshots.snapshot_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.snapshots.snapshot_identifier"]
  
end
coreo_aws_rule "redshift-inventory-cluster-subnet-groups" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Cluster Subnet Groups Inventory"
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
coreo_aws_rule "redshift-inventory-cluster-versions" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Cluster Versions Inventory"
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
coreo_aws_rule "redshift-inventory-hsm-client-certificates" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Hsm Client Certificates Inventory"
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
coreo_aws_rule "redshift-inventory-hsm-configurations" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Hsm Configurations Inventory"
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
coreo_aws_rule "redshift-inventory-orderable-cluster-options" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Orderable Cluster Options Inventory"
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
coreo_aws_rule "redshift-inventory-reserved-nodes" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Reserved Nodes Inventory"
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
coreo_aws_rule "redshift-inventory-snapshot-copy-grants" do
  service :Redshift
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Redshift Snapshot Copy Grants Inventory"
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
  rules ["redshift-inventory-clusters", "redshift-inventory-events", "redshift-inventory-event-categories", "redshift-inventory-event-subscriptions", "redshift-inventory-cluster-parameter-groups", "redshift-inventory-cluster-snapshots", "redshift-inventory-cluster-subnet-groups", "redshift-inventory-cluster-versions", "redshift-inventory-hsm-client-certificates", "redshift-inventory-hsm-configurations", "redshift-inventory-orderable-cluster-options", "redshift-inventory-reserved-nodes", "redshift-inventory-snapshot-copy-grants"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "rekognition-inventory-collections" do
  service :Rekognition
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Rekognition Collections Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "resourcegroupstaggingapi-inventory-tag-keys" do
  service :ResourceGroupsTaggingAPI
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ResourceGroupsTaggingAPI Tag Keys Inventory"
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
  rules ["resourcegroupstaggingapi-inventory-tag-keys"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "route53-inventory-reusable-delegation-sets" do
  service :Route53
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53 Reusable Delegation Sets Inventory"
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
  rules ["route53-inventory-reusable-delegation-sets", "route53-inventory-traffic-policies", "route53-inventory-traffic-policy-instances"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "route53domains-inventory-domains" do
  service :Route53Domains
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Route53Domains Domains Inventory"
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
  display_name "Route53Domains Operations Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "s3-inventory-buckets" do
  service :S3
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "S3 Buckets Inventory"
  description "This rule performs an inventory on the S3 service using the list_buckets function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_buckets"]
  audit_objects ["object.bucket.bucket_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.bucket.bucket_name"]
  
end
  
coreo_aws_rule_runner "s3-inventory-runner" do
  action :run
  service :S3
  rules ["s3-inventory-buckets"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "ses-inventory-identities" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Identities Inventory"
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
coreo_aws_rule "ses-inventory-send-statistics" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Send Statistics Inventory"
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
coreo_aws_rule "ses-inventory-configuration-sets" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Configuration Sets Inventory"
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
coreo_aws_rule "ses-inventory-receipt-filters" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Receipt Filters Inventory"
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
coreo_aws_rule "ses-inventory-receipt-rule-sets" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Receipt Rule Sets Inventory"
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
coreo_aws_rule "ses-inventory-verified-email-addresses" do
  service :SES
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SES Verified Email Addresses Inventory"
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
  rules ["ses-inventory-identities", "ses-inventory-send-statistics", "ses-inventory-configuration-sets", "ses-inventory-receipt-filters", "ses-inventory-receipt-rule-sets", "ses-inventory-verified-email-addresses"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "sms-inventory-connectors" do
  service :SMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SMS Connectors Inventory"
  description "This rule performs an inventory on the SMS service using the get_connectors function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["get_connectors"]
  audit_objects ["object.connector_list.connector_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.connector_list.connector_id"]
  
end
coreo_aws_rule "sms-inventory-replication-jobs" do
  service :SMS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SMS Replication Jobs Inventory"
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
  display_name "SMS Servers Inventory"
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
  rules ["sms-inventory-connectors", "sms-inventory-replication-jobs", "sms-inventory-servers"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "sns-inventory-platform-applications" do
  service :SNS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SNS Platform Applications Inventory"
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
  display_name "SNS Subscriptions Inventory"
  description "This rule performs an inventory on the SNS service using the list_subscriptions function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_subscriptions"]
  audit_objects ["object.subscriptions.subscription_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.subscriptions.subscription_arn"]
  
end
coreo_aws_rule "sns-inventory-topics" do
  service :SNS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SNS Topics Inventory"
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
  rules ["sns-inventory-platform-applications", "sns-inventory-subscriptions", "sns-inventory-topics"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "sqs-inventory-queues" do
  service :SQS
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SQS Queues Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "ssm-inventory-activations" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Activations Inventory"
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
coreo_aws_rule "ssm-inventory-automation-executions" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Automation Executions Inventory"
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
coreo_aws_rule "ssm-inventory-maintenance-windows" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Maintenance Windows Inventory"
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
  display_name "SSM Parameters Inventory"
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
coreo_aws_rule "ssm-inventory-patch-groups" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Patch Groups Inventory"
  description "This rule performs an inventory on the SSM service using the describe_patch_groups function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_patch_groups"]
  audit_objects ["object.mappings.patch_group"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.mappings.patch_group"]
  
end
coreo_aws_rule "ssm-inventory-associations" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Associations Inventory"
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
coreo_aws_rule "ssm-inventory-command-invocations" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Command Invocations Inventory"
  description "This rule performs an inventory on the SSM service using the list_command_invocations function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_command_invocations"]
  audit_objects ["object.command_invocations.command_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.command_invocations.command_id"]
  
end
coreo_aws_rule "ssm-inventory-commands" do
  service :SSM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SSM Commands Inventory"
  description "This rule performs an inventory on the SSM service using the list_commands function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_commands"]
  audit_objects ["object.commands.command_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.commands.command_id"]
  
end
  
coreo_aws_rule_runner "ssm-inventory-runner" do
  action :run
  service :SSM
  rules ["ssm-inventory-activations", "ssm-inventory-automation-executions", "ssm-inventory-maintenance-windows", "ssm-inventory-parameters", "ssm-inventory-patch-groups", "ssm-inventory-associations", "ssm-inventory-command-invocations", "ssm-inventory-commands"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "servicecatalog-inventory-accepted-portfolio-shares" do
  service :ServiceCatalog
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ServiceCatalog Accepted Portfolio Shares Inventory"
  description "This rule performs an inventory on the ServiceCatalog service using the list_accepted_portfolio_shares function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_accepted_portfolio_shares"]
  audit_objects ["object.portfolio_details.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.portfolio_details.id"]
  
end
coreo_aws_rule "servicecatalog-inventory-portfolios" do
  service :ServiceCatalog
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ServiceCatalog Portfolios Inventory"
  description "This rule performs an inventory on the ServiceCatalog service using the list_portfolios function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_portfolios"]
  audit_objects ["object.portfolio_details.id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.portfolio_details.id"]
  
end
  
coreo_aws_rule_runner "servicecatalog-inventory-runner" do
  action :run
  service :ServiceCatalog
  rules ["servicecatalog-inventory-accepted-portfolio-shares", "servicecatalog-inventory-portfolios"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "shield-inventory-attacks" do
  service :Shield
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Shield Attacks Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "simpledb-inventory-domains" do
  service :SimpleDB
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "SimpleDB Domains Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "snowball-inventory-addresses" do
  service :Snowball
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Snowball Addresses Inventory"
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
  display_name "Snowball Jobs Inventory"
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
  display_name "Snowball Clusters Inventory"
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
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "states-inventory-activities" do
  service :States
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "States Activities Inventory"
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
coreo_aws_rule "states-inventory-state-machines" do
  service :States
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "States State Machines Inventory"
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
  rules ["states-inventory-activities", "states-inventory-state-machines"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "storagegateway-inventory-tape-archives" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Tape Archives Inventory"
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
coreo_aws_rule "storagegateway-inventory-file-shares" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway File Shares Inventory"
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
  display_name "StorageGateway Gateways Inventory"
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
  display_name "StorageGateway Tapes Inventory"
  description "This rule performs an inventory on the StorageGateway service using the list_tapes function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_tapes"]
  audit_objects ["object.tape_infos.tape_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.tape_infos.tape_arn"]
  
end
coreo_aws_rule "storagegateway-inventory-volumes" do
  service :StorageGateway
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "StorageGateway Volumes Inventory"
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
  rules ["storagegateway-inventory-tape-archives", "storagegateway-inventory-file-shares", "storagegateway-inventory-gateways", "storagegateway-inventory-tapes", "storagegateway-inventory-volumes"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "waf-inventory-rules" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Rules Inventory"
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
coreo_aws_rule "waf-inventory-byte-match-sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Byte Match Sets Inventory"
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
coreo_aws_rule "waf-inventory-ip-sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Ip Sets Inventory"
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
coreo_aws_rule "waf-inventory-size-constraint-sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Size Constraint Sets Inventory"
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
coreo_aws_rule "waf-inventory-sql-injection-match-sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Sql Injection Match Sets Inventory"
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
coreo_aws_rule "waf-inventory-web-acls" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Web Acls Inventory"
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
coreo_aws_rule "waf-inventory-xss-match-sets" do
  service :WAF
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAF Xss Match Sets Inventory"
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
  rules ["waf-inventory-rules", "waf-inventory-byte-match-sets", "waf-inventory-ip-sets", "waf-inventory-size-constraint-sets", "waf-inventory-sql-injection-match-sets", "waf-inventory-web-acls", "waf-inventory-xss-match-sets"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "wafregional-inventory-rules" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Rules Inventory"
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
coreo_aws_rule "wafregional-inventory-byte-match-sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Byte Match Sets Inventory"
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
coreo_aws_rule "wafregional-inventory-ip-sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Ip Sets Inventory"
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
coreo_aws_rule "wafregional-inventory-size-constraint-sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Size Constraint Sets Inventory"
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
coreo_aws_rule "wafregional-inventory-sql-injection-match-sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Sql Injection Match Sets Inventory"
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
coreo_aws_rule "wafregional-inventory-web-acls" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Web Acls Inventory"
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
coreo_aws_rule "wafregional-inventory-xss-match-sets" do
  service :WAFRegional
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WAFRegional Xss Match Sets Inventory"
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
  rules ["wafregional-inventory-rules", "wafregional-inventory-byte-match-sets", "wafregional-inventory-ip-sets", "wafregional-inventory-size-constraint-sets", "wafregional-inventory-sql-injection-match-sets", "wafregional-inventory-web-acls", "wafregional-inventory-xss-match-sets"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
coreo_aws_rule "workspaces-inventory-workspace-bundles" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Workspace Bundles Inventory"
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
coreo_aws_rule "workspaces-inventory-workspace-directories" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Workspace Directories Inventory"
  description "This rule performs an inventory on the WorkSpaces service using the describe_workspace_directories function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_workspace_directories"]
  audit_objects ["object.directories.directory_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.directories.directory_name"]
  
end
coreo_aws_rule "workspaces-inventory-workspaces" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Workspaces Inventory"
  description "This rule performs an inventory on the WorkSpaces service using the describe_workspaces function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["describe_workspaces"]
  audit_objects ["object.workspaces.user_name"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.workspaces.user_name"]
  
end
coreo_aws_rule "workspaces-inventory-workspaces-connection-status" do
  service :WorkSpaces
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "WorkSpaces Workspaces Connection Status Inventory"
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
  rules ["workspaces-inventory-workspace-bundles", "workspaces-inventory-workspace-directories", "workspaces-inventory-workspaces", "workspaces-inventory-workspaces-connection-status"]
  regions ${AUDIT_AWS_INVENTORY_REGIONS}
end
