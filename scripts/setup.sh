#!/bin/bash

# global constants
DEV_NULL="/dev/null"


# functions
die() {
    local msg="${1:-untitiled error}"
    local code="${2:-1}"

    echo "error: $msg" >&2
    exit "$code"
}

create_sg() {
    local name="$1"
    local desc="$2"
    local vpc_id="$3"

    if [[ -z "$name" ]]; then
        echo "(internal error) 'create_sg' is called with no security group name" >&2
        return 1
    fi

    if [[ -z "$desc" ]]; then
        echo "(internal error) 'create_sg' is called with no security group description" >&2
        return 1
    fi

    if [[ -z "$vpc_id" ]]; then
        echo "(internal error) 'create_sg' is called with no vpc id"
        return 1
    fi

    local id
    id=$(aws ec2 create-security-group \
        --group-name "${name}" \
        --description "${desc}" \
        --vpc-id "${vpc_id}" \
        --query 'GroupId' \
        --output text) || return "$?"

    echo "$id"
}

allow_incoming_traffic_on_port_ipv4_for_sg() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local description="$5"

    if [[ -z "$sg_id" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv4_for_sg' is called with sg_id" >&2
        return 1
    fi

    if [[ -z "$protocol" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv4_for_sg' is called with protocol" >&2
        return 1
    fi

    if [[ -z "$port" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv4_for_sg' is called with port" >&2
        return 1
    fi

    if [[ -z "$cidr" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv4_for_sg' is called with cidr" >&2
        return 1
    fi

    if [[ -z "$description" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv4_for_sg' is called with description" >&2
        return 1
    fi

    aws ec2 authorize-security-group-ingress \
        --group-id "$sg_id" \
        --ip-permissions \
          "IpProtocol=$protocol,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=$cidr,Description='$description'}]" > "$DEV_NULL" || return "$?"
}

allow_incoming_traffic_on_port_ipv6_for_sg() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local cidr="$4"
    local description="$5"

    if [[ -z "$sg_id" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv6_for_sg' is called with sg_id" >&2
        return 1
    fi

    if [[ -z "$protocol" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv6_for_sg' is called with protocol" >&2
        return 1
    fi

    if [[ -z "$port" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv6_for_sg' is called with port" >&2
        return 1
    fi

    if [[ -z "$cidr" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv6_for_sg' is called with cidr" >&2
        return 1
    fi

    if [[ -z "$description" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_ipv6_for_sg' is called with description" >&2
        return 1
    fi

    aws ec2 authorize-security-group-ingress \
        --group-id "$sg_id" \
        --ip-permissions \
          "IpProtocol=$protocol,FromPort=$port,ToPort=$port,Ipv6Ranges=[{CidrIpv6=$cidr,Description='$description'}]" > "$DEV_NULL" || return "$?"
}


allow_http_for_sg()  {
    local sg_id="$1"
    if [[ -z "$sg_id" ]]; then
        die "(internal error) 'allow_http_for_sg' is called with no argument"
    fi

    allow_incoming_traffic_on_port_ipv4_for_sg "$sg_id" "tcp" 80 "0.0.0.0/0" "Allow HTTP from all ipv4 addresses" || return "$?"
    allow_incoming_traffic_on_port_ipv6_for_sg "$sg_id" "tcp" 80 "::/0" "Allow HTTP from all ipv6 addresses" || return "$?"
}

allow_https_for_sg() {
    local sg_id="$1"
    if [[ -z "$sg_id" ]]; then
        die "(internal error) 'allow_http_for_sg' is called with no argument"
    fi

    allow_incoming_traffic_on_port_ipv4_for_sg "$sg_id" "tcp" 443 "0.0.0.0/0" "Allow HTTPs from all ipv4 addresses" || return "$?"
    allow_incoming_traffic_on_port_ipv6_for_sg "$sg_id" "tcp" 443 "::/0" "Allow HTTPs from all ipv6 addresses" || return "$?"
}


# configurable variables
vpc_id="vpc-0c39a1bc674978444"


# create security groups
lb_secg_name="secg-lb"
lb_secg_desc="Security group for load balancer"

lb_secg_id=$(create_sg "$lb_secg_name" "$lb_secg_desc" "$vpc_id") || die "Failed to create security group $lb_secg_name" "$?"
allow_http_for_sg "$lb_secg_id" || die "Failed to allow HTTP for security group $lb_secg_id" "$?"
allow_https_for_sg "$lb_secg_id" || die "Failed to allow HTTPs for security group $lb_secg_id" "$?"

