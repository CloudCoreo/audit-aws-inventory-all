#!/usr/bin/env ruby
require 'aws-sdk'
require 'nokogiri'
require 'open-uri'
require 'yaml'

@specify_services = ["Route53"]

@global_ignorables = Regexp.union( /offerings$/ )

@modified_methods = {
  :EC2 => [{ :describe_images => { owners: ["self"] } }, { :describe_snapshots => { owner_ids: ["self"] } }]
}
@engine_bug_exclusions = {
  :EC2 => ["describe_images", "describe_snapshots"],
  :CloudTrail => ["list_public_keys"],
  :Route53 => ["get_checker_ip_ranges", "list_hosted_zones", "list_geo_locations"],
  :SSM => ["describe_available_patches", "describe_patch_baselines", "list_documents"]
}
@useless_methods = {
  :CodePipeline => ["list_action_types"],
  :DatabaseMigrationService => ["describe_account_attributes", "describe_endpoint_types"],
  :DirectConnect => ["describe_locations"],
  :CodeDeploy => ["list_deployment_configs"],
  :CodeBuild => ["list_curated_environment_images"],
  :CloudHSM => ["list_available_zones"],
  :CloudFormation => ["describe_account_limits"],
  :AutoScaling => ["describe_scaling_activities", "describe_adjustment_types", "describe_auto_scaling_notification_types", "describe_lifecycle_hook_types", "describe_metric_collection_types", "describe_scaling_process_types", "describe_termination_policy_types"],
  :EC2 => ["describe_reserved_instances_offerings"],
  :RDS => ["describe_reserved_db_instances_offerings"]

}

@yaml_doc = { 'variables' => {} }

def get_options(service_sym, method_sym)
  modified_service_call_hash = @modified_methods[service_sym]
  if modified_service_call_hash
    modified_service_call_hash.each { |m_hash|
      m_hash.each { |method, options|
        return options if method.eql?(method_sym)
      }
    }
  end
  return {}
end

def get_regions
  @ec2_regions = Aws::EC2::Client.new.describe_regions().regions.collect { |x| x.region_name }.sort
  return @ec2_regions
end

def addVariableToYaml(name, description=nil, required=nil, type=nil, default=nil)

  @yaml_doc['variables'][name] = {}
  @yaml_doc['variables'][name]['description'] = description unless description.nil?
  @yaml_doc['variables'][name]['required'] = required unless required.nil?
  @yaml_doc['variables'][name]['type'] = type unless type.nil?
  @yaml_doc['variables'][name]['default'] = default unless default.nil?

end

addVariableToYaml('AUDIT_AWS_INVENTORY_ALERT_RECIPIENT',
                  "Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.",
                  false,
                  "string")
addVariableToYaml('AUDIT_AWS_INVENTORY_ALLOW_EMPTY',
                  "Would you like to receive empty reports? Options - true / false. Default is false.",
                  true,
                  "string",
                  false)
addVariableToYaml('AUDIT_AWS_INVENTORY_SEND_ON',
                  "Send reports always or only when there is a change? Options - always / change. Default is change.",
                  true,
                  "string",
                  "change")
addVariableToYaml('AUDIT_AWS_INVENTORY_OWNER_TAG',
                  "Enter an AWS tag whose value is an email address of the owner of the AWS services being audited. (Optional)",
                  true,
                  "string",
                  "NOT_A_TAG")
addVariableToYaml('AUDIT_AWS_INVENTORY_REGIONS',
                  "List of AWS regions to check. Default is all regions. Choices are #{get_regions.join(',')}",
                  true,
                  "array",
                  get_regions)

def writeLine(line)
  open('./services/config.rb', 'a') { |f|
    f.puts line
  }
end

def compose_line(e)
  composition = []
  while e.next_element
    composition.push(e) unless e.text =~ /^#/
    break if e.next_element.attribute('class').text.eql? "id identifier rubyid_resp"
    e = e.next_element
  end
  return composition.join('')
end

def get_id_from_possibilities(possible_ids)
  search = [/arn\b/, /\.id/, /_id\b/, /_name\b/, /\[0\]/]
  found_possibilities = []
  search.each { |s|
    possible_ids.each { |pid|
      if pid =~ s
        id = pid.gsub('resp.', '')
        found_possibilities.push(id)
      end
    }
  }
  return "NA" if found_possibilities.size.eql?(0)
  sorted_possibilities = found_possibilities.sort_by { |x| x.count('.') }
  search.each { |s|
    sorted_possibilities.each { |pid|
      return pid.gsub('[0]', '') if pid =~ s
    }
  }
  return "NA"
end

@docs = {}

def getEntryFromHtml(service, method)
  url = "http://docs.aws.amazon.com/sdkforruby/api/Aws/#{service}/Client.html"
  doc = Nokogiri::HTML(open(url)) unless @docs[url]
  @docs[url] = doc if doc
  doc = @docs[url]
  method_doc = doc.at_css("[id=\"#{method}-instance_method\"]").parent
  tag_doc = method_doc.at_css('[class=tags]')
  example_doc = tag_doc.css('pre[class="example code"]').last
  example_doc_details = example_doc.css('span[class="id identifier rubyid_resp"]')
  possible_ids = []
  example_doc_details.each { |e|
    possible_ids.push(compose_line(e))
  }
  return get_id_from_possibilities(possible_ids)
end

@id_map = {}

Aws.partition('aws').services.each do |s|
  writeLine "# #{s.name}"
  if @specify_services
    next unless @specify_services.size > 0 && @specify_services.include?(s.name)
  end
  begin
    aws_client = eval("Aws::#{s.name}::Client.new")
  rescue Exception => e
    #writeLine "No Aws V2 Client found matching service #{s.name}" if aws_client.nil?
    next
  end

  relevant_methods = aws_client.methods.collect { |method| method if method =~ /(get|describe|list)/ }.compact.reject { |method| method.empty? || method =~ /tags/ || method !~ /s$/ }
  ## we have a client

  ## if it doesnt require and argument, it is an inventory method
  relevant_methods.each { |r|
    if @global_ignorables =~ r.to_s
      writeLine "#   - #{r} <- SKIPPING due to @global_ignorables"
      next
    end
    if @useless_methods[s.name.to_sym] && @useless_methods[s.name.to_sym].include?(r.to_s)
      writeLine "#   - #{r} <- SKIPPING due to @useless_methods"
      next
    end
    if @engine_bug_exclusions[s.name.to_sym] && @engine_bug_exclusions[s.name.to_sym].include?(r.to_s)
      writeLine "#   - #{r} <- SKIPPING due to @engine_bug_exclusions"
      next
    end
    begin
      opts = get_options(s.name.to_sym, r.to_sym)
      writeLine "#   - #{r}(#{opts})"
      aws_client.send(r.to_sym, opts)
      ## now check if we have a proper @id_map
      if !@id_map[aws_client.class.to_s.split('::')[1].to_sym] || !@id_map[aws_client.class.to_s.split('::')[1].to_sym][r.to_sym]
        id = getEntryFromHtml(aws_client.class.to_s.split('::')[1], r)
        if !@id_map[aws_client.class.to_s.split('::')[1].to_sym]
          @id_map[aws_client.class.to_s.split('::')[1].to_sym] = {}
          @id_map[aws_client.class.to_s.split('::')[1].to_sym][:methods] = {}
        end
        @id_map[aws_client.class.to_s.split('::')[1].to_sym][:methods][r.to_sym] = {}
        @id_map[aws_client.class.to_s.split('::')[1].to_sym][:methods][r.to_sym][:id] = id
        @id_map[aws_client.class.to_s.split('::')[1].to_sym][:methods][r.to_sym][:mod] = opts
        writeLine "#     - id: #{id}"
      end
      ## client per service
      @id_map[aws_client.class.to_s.split('::')[1].to_sym][:client] = aws_client if !@id_map[aws_client.class.to_s.split('::')[1].to_sym][:client]
    rescue Exception => e
      #raise "missing -> { :#{aws_client.class.to_s.split('::')[1]} => { :#{r} => \"#{id}\" }" if e.message.eql?("missing ID map")
      #writeLine "    method #{r} requires args"
    end
  }
end

@id_map.each_pair { |s, inv_hash|
  c = inv_hash[:client]
  service = s.to_s
  sClass = c.class.to_s.split('::')[1]
  service_rules = []
  inv_hash[:methods].each_pair { |method, m_hash|
    id = m_hash[:id]
    modifier = m_hash[:mod]
    next if id.eql?("NA")
    m = method.to_s
    rule_detail = "#{m.downcase.gsub('list_', '').gsub('describe_', '').gsub('get_', '').gsub('_', '-')}"
    rule_name = "#{service.downcase}-inventory-#{rule_detail}"
    service_rules.push(rule_name)
    writeLine <<-EOH
coreo_aws_rule "#{rule_name}" do
  service :#{service}
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "#{sClass} #{rule_detail.split('-').map(&:capitalize).join(' ')} Inventory"
  description "This rule performs an inventory on the #{sClass} service using the #{m} function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["#{m}"]
  audit_objects ["object.#{id}"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.#{id}"]
  #{modifier.empty? ? "" : "call_modifiers [#{modifier}]"}
end
    EOH
  }

  # addVariableToYaml("AUDIT_AWS_#{service.upcase}_ALERT_LIST",
  #                   "Which rules would you like to run? Possible values are #{service_rules.join(',')}",
  #                   false,
  #                   "array",
  #                   service_rules)

  region_string = "regions ${AUDIT_AWS_INVENTORY_REGIONS}"
  if @specify_services
    region_string = "regions ['us-east-1']"
  end
  writeLine <<-EOH
  
coreo_aws_rule_runner "#{service.downcase}-inventory-runner" do
  action :run
  service :#{service}
  rules #{service_rules}
  #{service.downcase.eql?("iam") ? "" : region_string}
end
  EOH
}
::File.write('./config.yaml', @yaml_doc.to_yaml)