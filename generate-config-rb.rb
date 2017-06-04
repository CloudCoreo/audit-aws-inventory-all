#!/usr/bin/env ruby
require 'aws-sdk'
require 'nokogiri'
require 'open-uri'
require 'yaml'

@yaml_doc = { 'variables' => {} }

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

def getEntryFromHtml(service, method)
  url = "http://docs.aws.amazon.com/sdkforruby/api/Aws/#{service}/Client.html"
  doc = Nokogiri::HTML(open(url))
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
    begin
      aws_client.send(r.to_sym, {})
      ## now check if we have a proper @id_map
      if !@id_map[aws_client.class.to_s.split('::')[1].to_sym] || !@id_map[aws_client.class.to_s.split('::')[1].to_sym][r.to_sym]
        id = getEntryFromHtml(aws_client.class.to_s.split('::')[1], r)
        if !@id_map[aws_client.class.to_s.split('::')[1].to_sym]
          @id_map[aws_client.class.to_s.split('::')[1].to_sym] = {}
          @id_map[aws_client.class.to_s.split('::')[1].to_sym][:methods] = {}
        end
        @id_map[aws_client.class.to_s.split('::')[1].to_sym][:methods][r.to_sym] = id
        writeLine "#   - #{r}"
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
  inv_hash[:methods].each_pair { |method, id|
    next if id.eql?("NA")
    m = method.to_s
    rule_name = "#{service.downcase}-inventory-#{m.downcase.gsub('list_', '').gsub('describe_', '').gsub('get_', '').gsub('-', '_')}"
    service_rules.push(rule_name)
    writeLine <<-EOH
coreo_aws_rule "#{rule_name}" do
  service :#{service}
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "#{sClass} Inventory"
  description "This rule performs an inventory on the #{sClass} service using the #{m} function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["#{m}"]
  audit_objects ["object.#{id}"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.#{id}"]
end
    EOH
  }

  # addVariableToYaml("AUDIT_AWS_#{service.upcase}_ALERT_LIST",
  #                   "Which rules would you like to run? Possible values are #{service_rules.join(',')}",
  #                   false,
  #                   "array",
  #                   service_rules)

  writeLine <<-EOH
  
coreo_aws_rule_runner "#{service.downcase}-inventory-runner" do
  action :run
  service :#{service}
  rules #{service_rules}
end
  EOH
}
::File.write('./config.yaml', @yaml_doc.to_yaml)