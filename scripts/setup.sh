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
        "IpProtocol=$protocol,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=$cidr,Description='$description'}]" >"$DEV_NULL" || return "$?"
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
        "IpProtocol=$protocol,FromPort=$port,ToPort=$port,Ipv6Ranges=[{CidrIpv6=$cidr,Description='$description'}]" >"$DEV_NULL" || return "$?"
}

allow_incoming_traffic_on_port_from_another_sg() {
    local sg_id="$1"
    local protocol="$2"
    local port="$3"
    local source_sg="$4"

    if [[ -z "$sg_id" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_from_another_sg' is called with no security group id" >&2
        return 1
    fi

    if [[ -z "$protocol" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_from_another_sg' is called with no protocol" >&2
        return 1
    fi

    if [[ -z "$port" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_from_another_sg' is called with no port" >&2
        return 1
    fi

    if [[ -z "$source_sg" ]]; then
        echo "(internal error) 'allow_incoming_traffic_on_port_from_another_sg' is called with no other security group id" >&2
        return 1
    fi

    aws ec2 authorize-security-group-ingress \
        --group-id "$sg_id" \
        --protocol "$protocol" \
        --port "$port" \
        --source-group "$source_sg" >"$DEV_NULL" || return "$?"
}

allow_traffic_within_sg() {
    local sg_id="$1"

    if [[ -z "$sg_id" ]]; then
        echo "(internal error) 'allow_traffic_within_sg' is called with no security group id" >&2
        return 1
    fi

    aws ec2 authorize-security-group-ingress \
        --group-id "$sg_id" \
        --protocol -1 \
        --source-group "$sg_id" >"$DEV_NULL" || return "$?"
}

allow_http_for_sg() {
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

allow_ssh_from_all_ips_for_sg() {
    local sg_id="$1"
    if [[ -z "$sg_id" ]]; then
        die "(internal error) 'allow_http_for_sg' is called with no argument"
    fi

    allow_incoming_traffic_on_port_ipv4_for_sg "$sg_id" "tcp" 22 "0.0.0.0/0" "Allow ssh from all ipv4 addresses" || return "$?"
    allow_incoming_traffic_on_port_ipv6_for_sg "$sg_id" "tcp" 22 "::/0" "Allow ssh from all ipv6 addresses" || return "$?"
}

create_key_pair() {
    local key_name="$1"
    if [[ -z "$key_name" ]]; then
        echo "(internal error) 'create_key_pair' was called with no key_name" >&2
        return 1
    fi

    aws ec2 create-key-pair \
        --key-name "$key_name" \
        --query 'KeyMaterial' \
        --output text >"$key_name".pem && chmod 400 "$key_name".pem
}

create_ec2_instance() {
    local ami_id="$1"
    local instance_type="$2"
    local key_name="$3"
    local secg_id="$4"
    local name="$5"
    local count="${6:-1}"
    local init_script_path="$7"
    local subnet_id="$8"

    if [[ -z "$ami_id" ]]; then
        echo "(internal error) 'create_ec2_instance' was called with no ami_id" >&2
        return 1
    fi

    if [[ -z "$instance_type" ]]; then
        echo "(internal error) 'create_ec2_instance' was called with no instance_type" >&2
        return 1
    fi

    if [[ -z "$key_name" ]]; then
        echo "(internal error) 'create_ec2_instance' was called with no key_name" >&2
        return 1
    fi

    if [[ -z "$secg_id" ]]; then
        echo "(internal error) 'create_ec2_instance' was called with no secg_id" >&2
        return 1
    fi

    local cmd="aws ec2 run-instances \
        --image-id $ami_id \
        --count $count \
        --instance-type $instance_type \
        --key-name $key_name \
        --security-group-ids $secg_id \
        --query 'Instances[0].InstanceId' \
        --output text \
        --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=$name}]' \
                             'ResourceType=volume,Tags=[{Key=Name,Value=disk-$name}]'"

    if [[ -n "$subnet_id" ]]; then
        cmd+=" --subnet-id $subnet_id"
    fi

    if [[ -n "$init_script_path" ]]; then
        cmd+=" --user-data file://$init_script_path"
    fi

    local output
    output=$(eval "$cmd") || return "$?"

    echo "$output"
}

get_instance_private_ip() {
    local instance_id="$1"
    if [[ -z "$instance_id" ]]; then
        echo "(internal error) 'get_instance_private_ip' is called with no instance_id" >&2
        return 1
    fi

    local private_ip
    private_ip=$(aws ec2 describe-instances \
        --instance-ids "$instance_id" \
        --query 'Reservations[0].Instances[0].PrivateIpAddress' \
        --output text) || return "$?"

    echo "$private_ip"
}

create_dns_route_53_private_hosted_zone() {
    local name="$1"
    local region="$2"
    local vpc_id="$3"
    local idempotency_token="$4"
    local comment="$5"

    if [[ -z "$name" ]]; then
        echo "(internal error) 'create_dns_route_53_private_hosted_zone' is called with no name" >&2
        return 1
    fi

    if [[ -z "$region" ]]; then
        echo "(internal error) 'create_dns_route_53_private_hosted_zone' is called with no region" >&2
        return 1
    fi

    if [[ -z "$vpc_id" ]]; then
        echo "(internal error) 'create_dns_route_53_private_hosted_zone' is called with no vpc_id" >&2
        return 1
    fi

    if [[ -z "$idempotency_token" ]]; then
        echo "(internal error) 'create_dns_route_53_private_hosted_zone' is called with no idempotency_token" >&2
        return 1
    fi

    if [[ -z "$comment" ]]; then
        echo "(internal error) 'create_dns_route_53_private_hosted_zone' is called with no comment" >&2
        return 1
    fi

    local output
    output=$(aws route53 create-hosted-zone \
        --name "$name" \
        --vpc VPCRegion="$region",VPCId="$vpc_id" \
        --caller-reference "$idempotency_token" \
        --hosted-zone-config Comment="$comment",PrivateZone=true \
        --query 'HostedZone.Id' \
        --output text) || return "$?"

    # remove the leading /hostedzone/ from the output
    local zone_id
    zone_id="${output#/hostedzone/}"

    echo "$zone_id"
}

create_change_record_set_string() {
    domain_name="$1"
    name_to_add="$2"
    private_ip="$3"

    if [[ -z "$domain_name" ]]; then
        echo "(internal error) 'create_change_record_set_string' is called with no domain_name" >&2
        return 1
    fi

    if [[ -z "$name_to_add" ]]; then
        echo "(internal error) 'create_change_record_set_string' is called with no name_to_add" >&2
        return 1
    fi

    if [[ -z "$private_ip" ]]; then
        echo "(internal error) 'create_change_record_set_string' is called with no private_ip" >&2
        return 1
    fi

    cat <<EOF
{
    "Action": "CREATE",
    "ResourceRecordSet": {
        "Name": "$name_to_add.$domain_name",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [
            { "Value": "$private_ip" }
        ]
    }
} 
EOF
}

update_hosted_zone_record_set() {
    local hosted_zone_id="$1"
    local changes_record_set="$2"

    if [[ -z "$hosted_zone_id" ]]; then
        echo "(internal error) 'change_hosted_zone_record_set' is called with no hosted_zone_id" >&2
        return 1
    fi

    if [[ -z "$changes_record_set" ]]; then
        echo "(internal error) 'change_hosted_zone_record_set' is called with no changes_record_set" >&2
        return 1
    fi

    local result
    result=$(aws route53 change-resource-record-sets \
        --hosted-zone-id "$hosted_zone_id" \
        --change-batch "$changes_record_set") || return "$?"

    # echo "$result"
}

get_instance_public_ip() {
    local instance_id="$1"
    if [[ -z "$instance_id" ]]; then
        echo "(internal error) 'get_instance_public_ip' is called with no instance_id" >&2
        return 1
    fi

    local public_ip
    public_ip=$(aws ec2 describe-instances \
        --instance-ids "$instance_id" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text | tr -d '[:space:]') || return "$?"

    echo "$public_ip" | tr -d '[:space:]'
}

wait_till_ec2_instance_is_running() {
    local instance_id="$1"
    if [[ -z "$instance_id" ]]; then
        echo "(internal error) 'wait_ec2_instance_is_running' is called with no instance_id" >&2
        return 1
    fi

    aws ec2 wait instance-running --instance-ids "$instance_id" || return "$?"
}

ssh_add_host_to_known_hosts() {
    local host="$1"
    if [[ -z "$host" ]]; then
        echo "(internal error) 'ssh_add_host_to_known_hosts' is called with no host" >&2
        return 1
    fi

    local fingerprint
    fingerprint=$(ssh-keyscan -H "$host") || return "$?"
    
    echo "$fingerprint"
    echo "$fingerprint" >> "$HOME/.ssh/known_hosts"
}

ssh_add_ec2_host_to_known_hosts() {
    local instance_id="$1"
    if [[ -z "$instance_id" ]]; then
        echo "(internal error) 'ssh_add_ec2_host_to_known_hosts' is called with no instance_id" >&2
        return 1
    fi

    local public_ip
    public_ip=$(get_instance_public_ip "$instance_id") || return "$?"
    ssh_add_host_to_known_hosts "$public_ip" || return "$?"
}

create_image_from_ec2_instance() {
    local instance_id="$1"
    local name="$2"
    local description="$3"
    if [[ -z "$instance_id" ]]; then
        echo "(internal error) 'create_image_from_ec2_instance' is called with no instance_id" >&2
        return 1
    fi

    if [[ -z "$name" ]]; then
        echo "(internal error) 'create_image_from_ec2_instance' is called with no name" >&2
        return 1
    fi

    if [[ -z "$description" ]]; then
        echo "(internal error) 'create_image_from_ec2_instance' is called with no description" >&2
        return 1
    fi

    local image_id
    image_id=$(aws ec2 create-image \
        --instance-id "$instance_id" \
        --name "$name" \
        --description "$description" \
        --query 'ImageId' \
        --output text) || return "$?"

    echo "$image_id"
}

wait_till_image_is_available() {
    local image_id="$1"
    if [[ -z "$image_id" ]]; then
        echo "(internal error) 'wait_till_image_is_available' is called with no image_id" >&2
        return 1
    fi

    aws ec2 wait image-available --image-ids "$image_id" || return "$?"
}

create_launch_template() {
    local template_name="$1"
    local description="$2"
    local image_id="$3"
    local instance_type="$4"
    local key_name="$5"
    local name_tag="$6"
    local security_groups_ids_arr=("${@:7}")

    if [[ -z "$template_name" ]]; then
        echo "(internal error) 'create_launch_template' is called with no template_name" >&2
        return 1
    fi

    if [[ -z "$description" ]]; then
        echo "(internal error) 'create_launch_template' is called with no description" >&2
        return 1
    fi

    if [[ -z "$image_id" ]]; then
        echo "(internal error) 'create_launch_template' is called with no image_id" >&2
        return 1
    fi

    if [[ -z "$instance_type" ]]; then
        echo "(internal error) 'create_launch_template' is called with no instance_type" >&2
        return 1
    fi

    if [[ -z "$key_name" ]]; then
        echo "(internal error) 'create_launch_template' is called with no key_name" >&2
        return 1
    fi

    if [[ -z "$name_tag" ]]; then
        echo "(internal error) 'create_launch_template' is called with no name_tag" >&2
        return 1
    fi

    if [[ ${#security_groups_ids_arr[@]} -eq 0 ]]; then
        echo "(internal error) 'create_launch_template' is called with no security_groups_ids" >&2
        return 1
    fi

    local security_groups_ids_string
    security_groups_ids_string=$(printf '"%s",' "${security_groups_ids_arr[@]}")

    local template_id
    template_id=$(aws ec2 create-launch-template \
                    --launch-template-name "$template_name" \
                    --version-description "$description" \
                    --query "LaunchTemplate.LaunchTemplateId" \
                    --output text \
                    --launch-template-data "$(cat << EOF
{
    "ImageId": "$image_id", 
    "InstanceType": "$instance_type",
    "KeyName": "$key_name",
    "TagSpecifications": [
        {
            "ResourceType": "instance",
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "$name_tag"
                }
            ]
        },
        {
            "ResourceType": "volume",
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "disk-$name_tag"
                }
            ]
        }
    ],
    "SecurityGroupIds": [${security_groups_ids_string%,}]
}
EOF
)" 
                ) || return "$?"

    echo "$template_id"
}

# configurable variables
vpc_id="vpc-0c39a1bc674978444"
region="us-east-1"
key_name="key-vprofile"
key_path="./key-vprofile.pem"
amazon_2023_ami_id="ami-0953476d60561c955"
ubuntu_2404_ami_id="ami-0731becbf832f281e"
ubuntu_ami_default_username="ubuntu"
default_instance_type="t2.micro"
mariadb_instance_name="ec2-mariadb"
memcached_instance_name="ec2-memcached"
rabbitmq_instance_name="ec2-rabbitmq"
tomcat_instance_name="ec2-tomcat"
tomcat_template_name=""
mariadb_init_script_path="../vprofile-project/userdata/mysql.sh"
memcached_init_script_path="../vprofile-project/userdata/memcache.sh"
tomcat_server_init_script_path="../vprofile-project/userdata/tomcat_ubuntu.sh"
rabbitmq_init_script_path="../vprofile-project/userdata/rabbitmq.sh"
private_domain_name="vprofile.in"

lb_secg_name="secg-lb"
lb_secg_desc="Security group for load balancer"

web_server_secg_name="secg-web-server"
web_server_secg_desc="Security group of web server"

services_secg_name="secg-web-server-services"
services_secg_desc="Security group of web server services: mariadb, memcached, rabbitmq"

mariadb_dns_record_name="db"
memcached_dns_record_name="memcached"
rabbitmq_dns_record_name="rabbitmq"

application_properites_path="../vprofile-project/userdata/application.properties"
application_build_path="../vprofile-project"
application_war_path="../vprofile-project/target/vprofile-v2.war"

tomcat_service_name="tomcat10"

# create security groups
## load balancer security group
# lb_secg_id=$(create_sg "$lb_secg_name" "$lb_secg_desc" "$vpc_id") || die "Failed to create security group $lb_secg_name" "$?"
# allow_http_for_sg "$lb_secg_id" || die "Failed to allow HTTP for security group $lb_secg_id" "$?"
# allow_https_for_sg "$lb_secg_id" || die "Failed to allow HTTPs for security group $lb_secg_id" "$?"

# # ## web server security group
# web_server_secg_id=$(create_sg "$web_server_secg_name" "$web_server_secg_desc" "$vpc_id") || die "Failed to create security group $web_server_secg_name" "$?"
# allow_incoming_traffic_on_port_from_another_sg "$web_server_secg_id" "tcp" 8080 "$lb_secg_id" || die "Failed to allow requests from load balancer security group for $web_server_secg_id" "$?"
# allow_ssh_from_all_ips_for_sg "$web_server_secg_id" || die "Failed to allow ssh for $web_server_secg_name"

## web server services security group
# services_secg_id=$(create_sg "$services_secg_name" "$services_secg_desc" "$vpc_id") || die "Failed to create security group $services_secg_name" "$?"
# allow_incoming_traffic_on_port_from_another_sg "$services_secg_id" "tcp" 3306 "$web_server_secg_id" || die "Failed to allow requests from web server to mariadb" "$?"
# allow_incoming_traffic_on_port_from_another_sg "$services_secg_id" "tcp" 11211 "$web_server_secg_id" || die "Failed to allow requests from web server to memcached" "$?"
# allow_incoming_traffic_on_port_from_another_sg "$services_secg_id" "tcp" 5672 "$web_server_secg_id" || die "Failed to allow requests from web server to rabbitmq non ssl port" "$?"
# allow_incoming_traffic_on_port_from_another_sg "$services_secg_id" "tcp" 5671 "$web_server_secg_id" || die "Failed to allow requests from web server to rabbitmq ssl port" "$?"
# allow_ssh_from_all_ips_for_sg "$services_secg_id" || die "Failed to allow ssh for $services_secg_name" "$?"
# allow_traffic_within_sg "$services_secg_id" || die "Failed to allow traffic within web server services security group" "$?"

# create key
# create_key_pair "$key_name" || die "Failed to create the key" "$?"

# # create services instances
# mariadb_instance_id=$(create_ec2_instance "$amazon_2023_ami_id" "$default_instance_type" "$key_name" "$services_secg_id" "$mariadb_instance_name" 1 "$mariadb_init_script_path") || die "failed to create mariadb instance" "$?"
# memcached_instance_id=$(create_ec2_instance "$amazon_2023_ami_id" "$default_instance_type" "$key_name" "$services_secg_id" "$memcached_instance_name" 1 "$memcached_init_script_path") || die "failed to create memcached instance" "$?"
# rabbitmq_instance_id=$(create_ec2_instance "$amazon_2023_ami_id" "$default_instance_type" "$key_name" "$services_secg_id" "$rabbitmq_instance_name" 1 "$rabbitmq_init_script_path") || die "failed to create memcached instance" "$?"

# # create dns route 53 private hosted zone
# hosted_zone_id=$(create_dns_route_53_private_hosted_zone "$private_domain_name" "$region" "$vpc_id" "vprofile-$(date +%s)" "Private hosted zone for vprofile project") || die "Failed to create DNS route 53 private hosted zone" "$?"

# mariadb_instance_private_ip=$(get_instance_private_ip "$mariadb_instance_id") || die "Failed to get instance private ip" "$?"
# memcached_instance_private_ip=$(get_instance_private_ip "$memcached_instance_id") || die "Failed to get instance private ip" "$?"
# rabbitmq_instance_private_ip=$(get_instance_private_ip "$rabbitmq_instance_id") || die "Failed to get instance private ip" "$?"

# change_record_set_string=$(cat << EOF
# {
#     "Comment": "Add records of services needed by vprofile web server",
#     "Changes": [
#         $(create_change_record_set_string "$private_domain_name" "$mariadb_dns_record_name" "$mariadb_instance_private_ip"),
#         $(create_change_record_set_string "$private_domain_name" "$memcached_dns_record_name" "$memcached_instance_private_ip"),
#         $(create_change_record_set_string "$private_domain_name" "$rabbitmq_dns_record_name" "$rabbitmq_instance_private_ip")
#     ]
# }
# EOF
# )

# update_hosted_zone_record_set "$hosted_zone_id" "$change_record_set_string" || die "failed to change hosted zone record set" "$?"

# # # update the application.properties
# sed -i "s/^memcached\.active\.host=.*/mecached.active.host=$memcached_dns_record_name.$private_domain_name/" "$application_properites_path"
# sed -i "s/^rabbitmq\.address=.*/rabbitmq.address=$rabbitmq_dns_record_name.$private_domain_name/" "$application_properites_path"
# sed -i "s|^jdbc\.url=.*|jdbc.url=jdbc:mysql://$mariadb_dns_record_name.$private_domain_name:3306/accounts?useUnicode=true&characterEncoding=UTF-8&zeroDateTimeBehavior=convertToNull|" "$application_properites_path"

# build the application
# mvn -f "$application_build_path/pom.xml" clean install

# # # create web server instance
# tomcat_instance_id=$(create_ec2_instance "$ubuntu_2404_ami_id" "$default_instance_type" "$key_name" "$web_server_secg_id" "$tomcat_instance_name" 1 "$tomcat_server_init_script_path") || die "failed to create tomcat instance" "$?"
# wait_till_ec2_instance_is_running "$tomcat_instance_id"
# sleep 60

# # add the server fingerprint to the know hosts
# tomcat_public_ip=$(get_instance_public_ip "$tomcat_instance_id") || die "failed to get tomcat server public ip" "$?"
# echo "Ubuntu Tomcat Temporary Webserver Public IP: $tomcat_public_ip"
# ssh_add_host_to_known_hosts "$tomcat_public_ip" || die "failed to add the tomcat web server fingerprint to the know hosts" "$?"

# remove default tomcat ROOT folder
# ssh -i "$key_path" "$ubuntu_ami_default_username"@"$tomcat_public_ip" "sudo systemctl stop $tomcat_service_name; sudo rm -rf /var/lib/tomcat10/webapps/ROOT"
# # copy the build
# scp -i "$key_path" "$application_war_path" "$ubuntu_ami_default_username"@"$tomcat_public_ip":/tmp/vprofile.war || die "failed to copy the war file to the tomcat server" "$?"
# # deploying app 2
# ssh -i "$key_path" "$ubuntu_ami_default_username"@"$tomcat_public_ip" "sudo systemctl stop $tomcat_service_name; sudo rm -rf /var/lib/tomcat10/webapps/ROOT; sudo mv /tmp/vprofile.war /var/lib/tomcat10/webapps/ROOT.war; sudo systemctl enable $tomcat_service_name; sudo systemctl start $tomcat_service_name" || die "failed to deploy the war file to the tomcat server" "$?"

# # create image out of ubuntu tomcat webserver
# ubuntu_tomcat_webserver_image_id=$(create_image_from_ec2_instance "$tomcat_instance_id" "ubuntu-vprofile-tomcat-webserver" "Ubuntu Vprofile Tomcat Webserver") || die "failed to create image out of ubuntu tomcat webserver" "$?"
# wait_till_image_is_available "$ubuntu_tomcat_webserver_image_id" || die "failed to wait till image is available" "$?"

# create launch template out of the image id
# create_launch_template "template-ubuntu-tomcat-webserver" "v1 of ubuntu tomcat web server" "$ubuntu_tomcat_webserver_image_id" "$default_instance_type" "$key_name" "ec2-ubuntu-tomcat-web-server" "$web_server_secg_id" || die "failed to create launch template out of the image id" "$?"
