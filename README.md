audit Inventory
============================
This composite performs inventory on your AWS cloud objects


## Description
This composite scans AWS services and reports on the inventory of objects found

## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inventory/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_INVENTORY_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_INVENTORY_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_INVENTORY_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the AWS services being audited. (Optional)
  * default: NOT_A_TAG

### `AUDIT_AWS_INVENTORY_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are ap-northeast-1,ap-northeast-2,ap-south-1,ap-southeast-1,ap-southeast-2,ca-central-1,eu-central-1,eu-west-1,eu-west-2,sa-east-1,us-east-1,us-east-2,us-west-1,us-west-2
  * default: ap-northeast-1, ap-northeast-2, ap-south-1, ap-southeast-1, ap-southeast-2, ca-central-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1, us-east-1, us-east-2, us-west-1, us-west-2


## Optional variables with default

**None**


## Optional variables with no default

### `AUDIT_AWS_INVENTORY_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Inventory

## Categories
1. AWS Inventory



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inventory/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inventory/master/images/icon.png "icon")

