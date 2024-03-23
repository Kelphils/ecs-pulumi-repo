import pulumi
import json
import pulumi_aws as aws

#Use the same name and port for task definition and service
container_app_family="api-dev-container"
container_port=8080

# Get the current AWS region dynamically
current_region = aws.get_region()

# Create the VPC
vpc = aws.ec2.Vpc("convexityVpc",
    cidr_block="172.20.0.0/16",
    instance_tenancy="default",
    enable_dns_hostnames=True,
    tags={"Name": "convexitydevVpc"}
)

# Define availability zones
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

# Create private subnets
private_subnets = []
for i, az in enumerate(availability_zones):
    subnet_name = f"convexitydevVpc-private-{az}"
    subnet = aws.ec2.Subnet(subnet_name,
                            vpc_id=vpc.id,
                            cidr_block=f"172.20.{i + 10}.0/24",
                            tags={"Name": f"convexitydevVpc-private-{az}"},
                            availability_zone=az)
    private_subnets.append(subnet)

# Create public subnets
public_subnets = []
for i, az in enumerate(availability_zones):
    subnet_name = f"convexitydevVpc-public-{az}"
    subnet = aws.ec2.Subnet(subnet_name,
                            vpc_id=vpc.id,
                            map_public_ip_on_launch=True,
                            cidr_block=f"172.20.{i}.0/24",
                            tags={"Name": f"convexitydevVpc-public-{az}"},
                            availability_zone=az)
    public_subnets.append(subnet)

# Create an Internet Gateway
internet_gateway = aws.ec2.InternetGateway("igw",
    vpc_id=vpc.id)

# Allocate an Elastic IP (EIP) for the NAT Gateway
eip = aws.ec2.Eip("natEip",
                  tags={"Name": "convexitydevVpc-Eip"})

# Create the NAT Gateway
nat_gateway = aws.ec2.NatGateway("natGateway",
    allocation_id=eip.id,
    subnet_id=public_subnets[0].id,
    tags={"Name": "convexitydevVpc-nat"},
    opts=pulumi.ResourceOptions(depends_on=[internet_gateway]),)

# Create a public route table
public_route_table = aws.ec2.RouteTable("publicRouteTable",
    vpc_id=vpc.id,
    tags={"Name": "convexitydevVpc-public-rtb"},
    routes=[
        {
            "cidr_block": "0.0.0.0/0",
            "gateway_id": internet_gateway.id,
        }
    ])

# Associate public route table with public subnets
for i, subnet in enumerate(public_subnets):
    aws.ec2.RouteTableAssociation(f"public-{i}",
        subnet_id=subnet.id,
        route_table_id=public_route_table.id)

# Create a private route table
private_route_table = aws.ec2.RouteTable("privateRouteTable",
    vpc_id=vpc.id,
    tags={"Name": "convexitydevVpc-private-rtb"},
    routes=[
        {
            "cidr_block": "0.0.0.0/0",
            "nat_gateway_id": nat_gateway.id,
        }
    ])

# Associate private route table with private subnets
for i, subnet in enumerate(private_subnets):
    aws.ec2.RouteTableAssociation(f"private-{i}",
        subnet_id=subnet.id,
        route_table_id=private_route_table.id)


# Create an ECR repository
repo = aws.ecr.Repository("convex-repo",

    name="convexity-dev-repository",
    image_tag_mutability="MUTABLE",
    force_delete=True,
    image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(
        scan_on_push=True,
    ))

# Create an ECS Fargate cluster
cluster = aws.ecs.Cluster("convex-cluster",
    name="convexity-dev-cluster",
    tags={"Name": "convexity-dev-cluster"},
    settings=[aws.ecs.ClusterSettingArgs(
        name="containerInsights",
        value="enabled",
    )],
    )

# Hosted Zone
hosted_zone = aws.route53.get_zone(name="chats.cash")

# Create a subdomain for ECS
subdomain = f"ecs.{hosted_zone.name}"

# Define the security group for the ALB
alb_security_group = aws.ec2.SecurityGroup("alb-security-group",
    vpc_id=vpc.id,
    description="Security group for ECS Tasks",
    ingress=[
        {
            "protocol": "tcp",
            "from_port": 80,
            "to_port": 80,
            "cidr_blocks": ["0.0.0.0/0"],  # Allowing traffic from anywhere
        },
        {
            "protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "cidr_blocks": ["0.0.0.0/0"],  # Allowing traffic from anywhere
        },
    ],
    egress=[{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])

# Define the security group for ECS tasks
ecs_task_security_group = aws.ec2.SecurityGroup("ecs-task-security-group",
    vpc_id=vpc.id,
    description="Security group for ECS Tasks",
    ingress=[
        {
            "protocol": "-1",  # Allow all traffic
            "from_port": 0,
            "to_port": 0,
            "security_groups": [alb_security_group.id],  # Allow traffic from ALB security group
        },
    ],
    egress=[{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])

# Create the RDS security group
rds_priv_security_group = aws.ec2.SecurityGroup("rdsPrivSecurityGroup",
    description="Security group for RDS",
    vpc_id=vpc.id,
    ingress=[
        {
            "protocol": "tcp",
            "from_port": 5432,  # Postgres port
            "to_port": 5432,
            "security_groups": [ecs_task_security_group.id],  # Allow traffic from ECS task security group
        }
    ],
    egress=[{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])

rds_pub_security_group = aws.ec2.SecurityGroup("rdsPubSecurityGroup",
    description="Security group for RDS",
    vpc_id=vpc.id,
    ingress=[
        {
            "protocol": "tcp",
            "from_port": 5432,  # Postgres port
            "to_port": 5432,
            "cidr_blocks": ["0.0.0.0/0"],  # Allow traffic from Anywhere
        }
    ],
    egress=[{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])

# Create ACM Certificate
acm_certificate = aws.acm.Certificate("acm-certificate",
    domain_name=subdomain,
    validation_method="DNS",
)

# # Validation records for ACM Certificate
validation_record = aws.route53.Record("acm-validation-record",
    name=acm_certificate.domain_validation_options[0].resource_record_name,
    zone_id=hosted_zone.zone_id,  # Use hosted zone ID instead of resource_record_zone_id
    type=acm_certificate.domain_validation_options[0].resource_record_type,
    records=[acm_certificate.domain_validation_options[0].resource_record_value],
    ttl=60,
)


# Create an Application Load Balancer
alb = aws.lb.LoadBalancer("alb",
    name="convexity-dev",
    internal=False,
    load_balancer_type="application",
    security_groups=[alb_security_group.id],
    subnets=[subnet.id for subnet in public_subnets],
    enable_deletion_protection=False,
    tags={
        "Environment": "production",
    },
    opts=pulumi.ResourceOptions(depends_on=[validation_record, vpc]),
    )

# Create Route53 record for the subdomain pointing to the load balancer
dns_record = aws.route53.Record("ecs-record",
    zone_id=hosted_zone.zone_id,
    name=subdomain,
    type="A",
    aliases=[
        {
            "name": alb.dns_name,
            "zoneId": alb.zone_id,
            "evaluateTargetHealth": True,
        },
    ],
)

# Create an AWS CloudWatch Log Group
log_group = aws.cloudwatch.LogGroup("appLogGroup",
    retention_in_days=7,
    name="convex-dev-ecs-log-group",
)

# Create target groups for HTTP and HTTPS
alb_target_group = aws.lb.TargetGroup("httpTargetGroup",
    name="ecs-target-group",
    port=container_port,
    protocol="HTTP",
    protocol_version="HTTP1",
    deregistration_delay=30,
    target_type="ip",
    vpc_id=vpc.id)

# Create listener for HTTPS
https_listener = aws.lb.Listener("httpsListener",
    load_balancer_arn=alb.arn,
    port=443,
    protocol="HTTPS",
    certificate_arn=acm_certificate.arn,
    default_actions=[aws.lb.ListenerDefaultActionArgs(
        type="forward",
        target_group_arn=alb_target_group.arn,
    )],
    opts=pulumi.ResourceOptions(depends_on=[alb]),
)

# # Redirect action
redirect_http_to_https = aws.lb.Listener("redirect_http_to_https",
    load_balancer_arn=alb.arn,
    port=80,
    protocol="HTTP",
    default_actions=[aws.lb.ListenerDefaultActionArgs(
        type="redirect",
        redirect=aws.lb.ListenerDefaultActionRedirectArgs(
            port="443",
            protocol="HTTPS",
            status_code="HTTP_301",
        ),
    )],
    opts=pulumi.ResourceOptions(depends_on=[alb]),
)

# Create the RDS instance
# dev_rds_instance = aws.rds.Instance("rds",
#     identifier="dev-convexity-db",
#     instance_class="db.t3.micro",  # Example of a supported instance class for PostgreSQL
#     engine="postgres",
#     allocated_storage=100,
#     engine_version="14.11",  # Example of a supported engine version
#     db_name="apiserverdb",
#     username="convexity",
#     password="convexpassword",
#     publicly_accessible=True,
#     skip_final_snapshot=True,
#     vpc_security_group_ids=[rds_pub_security_group.id],
#     db_subnet_group_name=aws.rds.SubnetGroup("rds-subnet-group-private", subnet_ids=[subnet.id for subnet in private_subnets])
#     # db_subnet_group_name=aws.rds.SubnetGroup("rds-subnet-group-public", subnet_ids=[subnet.id for subnet in public_subnets]),
#     # storage_encrypted=True
# )

rds_instance = aws.rds.Instance("rds-staging",
    identifier="staging-convexity-db",
    instance_class="db.t3.micro",  # Example of a supported instance class for PostgreSQL
    engine="postgres",
    allocated_storage=100,
    engine_version="14.11",  # Example of a supported engine version
    db_name="apiserverdb",
    username="convexity",
    password="convexpassword",
    publicly_accessible=True,
    skip_final_snapshot=True,
    vpc_security_group_ids=[rds_pub_security_group.id],
    # db_subnet_group_name=aws.rds.SubnetGroup("rds-subnet-group-private", subnet_ids=[subnet.id for subnet in private_subnets])
    db_subnet_group_name=aws.rds.SubnetGroup("rds-subnet-group-public", subnet_ids=[subnet.id for subnet in public_subnets]),
    storage_encrypted=True
)

# Store credentials in AWS Secrets Manager
secret_manager = aws.secretsmanager.Secret("convexSecret",
    name="convex-dev-secrets",
    recovery_window_in_days=0
)

container_image=repo.repository_url
log_group_name=log_group.name
current_region_name=current_region.name
secret_name=secret_manager.name
secret_manager_arn=secret_manager.arn


# Store RDS details in SSM Parameter Store
db_endpoint = aws.ssm.Parameter("dbEndpointParam",
    name="/Convexity/dev/DbEndpoint",
    type="String",
    value=rds_instance.endpoint,
    overwrite=True,
)

db_name_param = aws.ssm.Parameter("dbNameParam",
    name="/Convexity/dev/DbName",
    type="String",
    value=rds_instance.db_name,
    overwrite=True,
)

# Assume role policy document
assume_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
                "Service": ["ecs.amazonaws.com","ecs-tasks.amazonaws.com"]
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}

# Create IAM role
ecs_exec_role = aws.iam.Role("ecs-exec-role",
    name="convex-dev-ecs-task-execution-role",
    assume_role_policy=assume_role_policy)

# Attach AmazonECSTaskExecutionRolePolicy to the ECS role
ecs_role_policy_attachment = aws.iam.RolePolicyAttachment("ecsExecRolePolicyAttachment",
    role=ecs_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")

# Define the ECS Assume role
task_role = aws.iam.Role("ssmRole",
    name="convex-dev-ecs-task-role",
    description="Policy that allows access to SSM",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                    "Service": "ecs-tasks.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }""",
)

# Define the SSM policy
ssm_policy = aws.iam.Policy("ssmPolicy",
    policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:*"
                ],
                "Resource": "*"
            }
        ]
    }""",
)

cloudwatch_policy = aws.iam.Policy("cloudwatchPolicy",
    policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": ["logs:PutLogEvents"],
                "Effect": "Allow",
                "Resource": ["*"]
            }
        ]
    }""",
)


# Define the secret manager policy
secrets_policy = aws.iam.Policy("secretManagerPolicy",
    policy=secret_manager.arn.apply(lambda arn: f"""{{
        "Version": "2012-10-17",
        "Statement": [
            {{
                "Sid": "AccessSecrets",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue"
                ],
                "Resource": "{arn}"
            }}
        ]
    }}"""),
)


# Define the KMS policy
kms_policy = aws.iam.Policy("kmsPolicy",
    policy="""{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "kms:*"
                ],
                "Resource": "*"
            }
        ]
    }""",
)

# Attach ssm policy to tthe ecs tasks role
attachment = aws.iam.RolePolicyAttachment("ssmPolicyAttachment",
    role=task_role.name,
    policy_arn=ssm_policy.arn,
)


# Attach SSMRolePolicy to the ecs exec role
ecs_role_policy_attachment = aws.iam.RolePolicyAttachment("ecsKmsRolePolicyAttachment",
    role=ecs_exec_role.name,
    policy_arn=ssm_policy.arn)

# Attach kms policy to tthe ecs tasks role
attachment = aws.iam.RolePolicyAttachment("kmsPolicyAttachment",
    role=task_role.name,
    policy_arn=kms_policy.arn,
)

# Attach KMSRolePolicy to the ecs exec role
ecs_role_policy_attachment = aws.iam.RolePolicyAttachment("ecsSsmRolePolicyAttachment",
    role=ecs_exec_role.name,
    policy_arn=kms_policy.arn)

# Attach the read secrets policy to the ECS Exec role
role_policy_attachment = aws.iam.RolePolicyAttachment("secretsrolePolicyAttachment",
    role=ecs_exec_role.name,
    policy_arn=secrets_policy.arn
)

# Attach put logs policy to the ECS Exec role
role_policy_attachment = aws.iam.RolePolicyAttachment("cloudwatchrolePolicyAttachment",
    role=ecs_exec_role.name,
    policy_arn=cloudwatch_policy.arn
)

# Attach the read secrets policy to the ECS task role
secrets_role_policy_attachment = aws.iam.RolePolicyAttachment("secretsPolicyAttachment",
    role=task_role.name,
    policy_arn=secrets_policy.arn
)

# Attach put logs policy to the ECS task role
cloudwatch_role_policy_attachment = aws.iam.RolePolicyAttachment("cloudwatchPolicyAttachment",
    role=task_role.name,
    policy_arn=cloudwatch_policy.arn
)

# Get the value of DB endpoint parameter
db_endpoint_value = db_endpoint.value

db_name_param_value = db_name_param.value

# Get the values of DB from secret manager
secret_version = pulumi.Output.all(
    secret_manager.id,
    rds_instance.username,
    rds_instance.password,
    rds_instance.db_name,
    rds_instance.address
).apply(lambda values: aws.secretsmanager.SecretVersion("secretVersion",
    secret_id=values[0],
    secret_string=json.dumps({
        "DB_USER": values[1],
        "DB_PASSWORD": values[2],
        "DB_NAME": values[3],
        "DB_HOST": values[4],
    })
))

# ECS task definition
task_definition = aws.ecs.TaskDefinition("appTaskDef",
    family=container_app_family,
    cpu="512",
    memory="1024",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    task_role_arn=task_role.arn,
    execution_role_arn=ecs_exec_role.arn,
    runtime_platform=aws.ecs.TaskDefinitionRuntimePlatformArgs(
        operating_system_family="LINUX",
        cpu_architecture="X86_64",
    ),
    container_definitions=pulumi.Output.all(container_image, log_group_name, current_region_name, db_endpoint_value, container_app_family, container_port, secret_name, secret_manager_arn, db_name_param_value).apply(lambda args: json.dumps([
        {
            "name": args[4],
            "image": args[0],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": args[1],
                    "awslogs-region": args[2],
                    "awslogs-stream-prefix": "ecs"
                }
            },
            "portMappings": [
                {
                    "containerPort": args[5],
                    "hostPort": args[5],
                    "protocol": "tcp"
                }
            ],
            "secrets": [
                {
                    "name": args[6],
                    "valueFrom": args[7]
                }
            ],
            "environment": [
                {
                    "name": "DATABASE_HOST",
                    "value": args[3]
                },
                {
                    "name": "DATABASE_NAME",
                    "value": args[8]
                },
            ]
        }
    ])),
    tags={"appFamily": container_app_family},
    opts=pulumi.ResourceOptions(depends_on=[repo])
)

# Here we use the Application Load Balancer for the ECS service
ecs_service = aws.ecs.Service("appService",
    name="convex-dev-ecs-tasks-service",
    cluster=cluster,
    task_definition=task_definition.arn,
    desired_count=1,
    enable_execute_command=True,
    deployment_minimum_healthy_percent=50,
    deployment_maximum_percent=200,
    force_new_deployment=True,
    health_check_grace_period_seconds=60,
    launch_type="FARGATE",
    scheduling_strategy="REPLICA",
    propagate_tags="TASK_DEFINITION",
    network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
        subnets=private_subnets,
        security_groups=[ecs_task_security_group],
        assign_public_ip=False,
    ),
    # enable this for rolling deployment
    deployment_circuit_breaker=aws.ecs.ServiceDeploymentCircuitBreakerArgs(
        enable=True,
        rollback=True,
    ),
    load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
        target_group_arn=alb_target_group.arn,
        container_name=container_app_family,
        container_port=container_port
    )],
    opts=pulumi.ResourceOptions(depends_on=[repo, cluster, task_definition, alb])
)

# Ecs Autoscaling Target for CPU
ecs_target = aws.appautoscaling.Target("ecs_target",
    max_capacity=4,
    min_capacity=1,
    resource_id=pulumi.Output.all(cluster.name, ecs_service.name).apply(lambda args: f"service/{args[0]}/{args[1]}"),
    scalable_dimension="ecs:service:DesiredCount",
    service_namespace="ecs"
)

# Create an autoscaling policy for CPU
autoscaling_policy_cpu = aws.appautoscaling.Policy("app-scaling-policy_cpu",
    name="ecs-scaling-policy",
    policy_type="TargetTrackingScaling",
    resource_id=pulumi.Output.all(cluster.name, ecs_service.name).apply(lambda args: f"service/{args[0]}/{args[1]}"),
    scalable_dimension=ecs_target.scalable_dimension,
    service_namespace=ecs_target.service_namespace,
    target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
        predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
            predefined_metric_type="ECSServiceAverageCPUUtilization"
        ),
        target_value=80,
        scale_in_cooldown=300,
        scale_out_cooldown=300,
    )
)

# Create an autoscaling policy for memory
autoscaling_policy_mem = aws.appautoscaling.Policy("app-scaling-policy_mem",
    name="ecs-scaling-policy",
    policy_type="TargetTrackingScaling",
    resource_id=pulumi.Output.all(cluster.name, ecs_service.name).apply(lambda args: f"service/{args[0]}/{args[1]}"),
    scalable_dimension=ecs_target.scalable_dimension,
    service_namespace=ecs_target.service_namespace,
    target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
        predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
            predefined_metric_type="ECSServiceAverageMemoryUtilization"
        ),
        target_value=80,
        scale_in_cooldown=300,
        scale_out_cooldown=300,
    ),
    opts=pulumi.ResourceOptions(depends_on=[ecs_target, autoscaling_policy_cpu])
)

# Outputs
pulumi.export('task_definition_name', task_definition.family)
pulumi.export('container_name', container_app_family)
pulumi.export('repository_url', repo.repository_url)
pulumi.export('service_name', ecs_service.name)
pulumi.export('cluster_name', cluster.name)
pulumi.export('registry_name', repo.name)
pulumi.export('ecs_endpoint', subdomain),
for i, subnet in enumerate(private_subnets):
    pulumi.export(f"private_subnet_{i}", {
        "id": subnet.id,
        "cidr_block": subnet.cidr_block,
        "availability_zone": subnet.availability_zone,
    })

for i, subnet in enumerate(public_subnets):
    pulumi.export(f"public_subnet_{i}", {
        "id": subnet.id,
        "cidr_block": subnet.cidr_block,
        "availability_zone": subnet.availability_zone,
    })

# task_definition = aws.ecs.TaskDefinition("appTaskDef",
#     family=container_app_family,
#     cpu="512",
#     memory="1024",
#     network_mode="awsvpc",
#     requires_compatibilities=["FARGATE"],
#     task_role_arn=task_role.arn,
#     execution_role_arn=ecs_exec_role.arn,
#     runtime_platform=aws.ecs.TaskDefinitionRuntimePlatformArgs(
#         operating_system_family="LINUX",
#         cpu_architecture="X86_64",
#     ),
#     container_definitions=pulumi.Output.all(container_image, log_group_name, current_region_name, db_endpoint_value, container_app_family, container_port, secret_name, secret_manager_arn, db_name_param_value).apply(lambda args: json.dumps([
#         {
#             "name": args[4],
#             "image": args[0],
#             "command": [
#                 "pnpm",
#                 "run",
#                 "db:generate-staging",
#                 "&&",
#                 "pnpm",
#                 "run",
#                 "db:push-staging",
#                 "&&",
#                 "pnpm",
#                 "run",
#                 "build",
#                 "&&",
#                 "pnpm",
#                 "start"
#             ],
#             "logConfiguration": {
#                 "logDriver": "awslogs",
#                 "options": {
#                     "awslogs-group": args[1],
#                     "awslogs-region": args[2],
#                     "awslogs-stream-prefix": "ecs"
#                 }
#             },
#             "portMappings": [
#                 {
#                     "containerPort": args[5],
#                     "hostPort": args[5],
#                     "protocol": "tcp"
#                 }
#             ],
#             "secrets": [
#                 {
#                     "name": args[6],
#                     "valueFrom": args[7]
#                 }
#             ],
#             "environment": [
#                 {
#                     "name": "DATABASE_HOST",
#                     "value": args[3]
#                 },
#                 {
#                     "name": "DATABASE_NAME",
#                     "value": args[8]
#                 },
#             ]
#         }
#     ])),
#     tags={"appFamily": container_app_family},
#     opts=pulumi.ResourceOptions(depends_on=[repo])
# )