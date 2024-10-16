### PowerVC Details
auth_url                    = "<https://<HOSTNAME>:5000/v3/>"
user_name                   = "<powervc-login-user-name>"
password                    = "<powervc-login-user-password>"
tenant_name                 = "<tenant_name>"
domain_name                 = "Default"
openstack_availability_zone = ""

network_name = "<network_name>"

### OpenShift Cluster Details

ceph   = { instance_type = "<ceph-compute-template>", image_id = "<image-uuid-rhel>", "count" = 3, data_volume_count  = 1, data_volume_size  = 500 }

# With all optional attributes
# ceph                     = {instance_type    = "<ceph-compute-template>",   image_id    = "<image-uuid-rhel>",   availability_zone = "<availability zone>",  "count"   = 3, fixed_ip_v4 = "<IPv4 address>", data_volume_count  = 1, data_volume_size  = 500}

ceph_repo = "http://<>>/ceph-6/" # Repository where ppc64le rpms available

rhel_username                   = "root" #Set it to an appropriate username for non-root user access
public_key_file                 = "data/id_rsa.pub"
private_key_file                = "data/id_rsa"
rhel_subscription_username      = "<subscription-id>"       #Leave this as-is if using CentOS as ceph image
rhel_subscription_password      = "<subscription-password>" #Leave this as-is if using CentOS as ceph image
rhel_subscription_org           = ""                        # Define it only when using activationkey for RHEL subscription
rhel_subscription_activationkey = ""                        # Define it only when using activationkey for RHEL subscription

connection_timeout = 45

cluster_domain    = "nip.io"  # Set domain to nip.io or xip.io if you prefer using online wildcard domain and avoid modifying /etc/hosts
cluster_id_prefix = "ceph" # Set it to empty if just want to use cluster_id without prefix
cluster_id        = ""         # It will use random generated id with cluster_id_prefix if this is not set

### Misc Customizations

#network_type               = "SRIOV"
#scg_id                     = "df21cec9-c244-4d3d-b927-df1518672e87"
#sriov_vnic_failover_vfs    = 1
#sriov_capacity             = 0.02

#chrony_config              = true
#chrony_config_servers      = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]
