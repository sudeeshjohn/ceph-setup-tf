# How to use var.tfvars

- [How to use var.tfvars](#how-to-use-vartfvars)
  - [Introduction](#introduction)
    - [PowerVC Details](#powervc-details)
    - [OpenShift Cluster Details](#openshift-cluster-details)
    - [OpenShift Installation Details](#openshift-installation-details)
    - [Misc Customizations](#misc-customizations)


## Introduction

This guide gives an overview of the various terraform variables that are used for the deployment.
The default values are set in [variables.tf](../variables.tf)

### PowerVC Details

These set of variables specify the PowerVC details.

```
auth_url                    = "<https://<HOSTNAME>:5000/v3/>"
user_name                   = "<powervc-login-user-name>"
password                    = "<powervc-login-user-password>"
tenant_name                 = "<tenant_name>"
domain_name                 = "Default"
```

This variable specifies the network that will be used by the VMs
```
network_name                = "<network_name>"
```

This variable specifies the availability zone (PowerVC Host Group) in which to create the VMs. Leave it empty to use the "default" availability zone.
```
openstack_availability_zone = ""
```

### OpenShift Cluster Details

These set of variables specify the cluster capacity.

```
ceph                     = {instance_type    = "<ceph-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 3, data_volume_count = 1,  data_volume_size = 500 }

```

`instance_type` is the compute template to be used and `image_id` is the image UUID. `count` specifies the number of VMs that should be created for each type.

To enable high availability (HA) for cluster services running on the ceph set the ceph `count` value to 2. Note that in case of HA, the automation will not setup NFS storage. `count` of 1 for ceph implies the default non-HA ceph setup.

You can optionally set worker `count` value to 0 in which case all the cluster pods will be running on the master/supervisor nodes.
Ensure you use proper sizing for master/supervisor nodes to avoid resource starvation for containers.

`availability_zone` is an optional attribute for ceph, bootstrap, master and worker. If it is specified, the VM will be created in the specified `availability_zone`, otherwise value of `openstack_availability_zone` will be used.
```
ceph                     = {instance_type    = "<ceph-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 3, , data_volume_count = 1,  data_volume_size = 500}
```
Above will create the ceph in `openstack_availability_zone`, bootstrap in default availability zone, masters in `master-zone`, and workers in `worker-zone`.

To set a pre-defined IPv4 address for the ceph node, make use of the optional `fixed_ip_v4` in ceph variable as shown below. Ensure this address is within the given network subnet range and not already in use.
```
ceph                     = {instance_type    = "<ceph-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 1,  fixed_ip_v4 = "<IPv4 address>"}
```
For ceph cluster with pre-defined IPs, here the `fixed_ip_v4` will be the VIP for cephs:
```
ceph                     = {instance_type    = "<ceph-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 2,  fixed_ip_v4 = "<IPv4 address>", fixed_ips = ["<IPv4 address>", "<IPv4 address>"]}
```
These set of variables specify the username and the SSH key to be used for accessing the ceph node.
```
rhel_username               = "root"  #Set it to an appropriate username for non-root user access
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
```
rhel_username is set to root. rhel_username can be set to an appropriate username having superuser privileges with no password prompt.
Please note that only OpenSSH formatted keys are supported. Refer to the following links for instructions on creating SSH key based on your platform.
- Windows 10 - https://phoenixnap.com/kb/generate-ssh-key-windows-10
- Mac OSX - https://www.techrepublic.com/article/how-to-generate-ssh-keys-on-macos-mojave/
- Linux - https://www.siteground.com/kb/generate_ssh_key_in_linux/

Create the SSH key-pair and keep it under the `data` directory

These set of variables specify the RHEL subscription details, RHEL subscription supports two methods: one is using username and password, the other is using activation key.
This is sensitive data, and if you don't want to save it on disk, use environment variables `RHEL_SUBS_USERNAME` and `RHEL_SUBS_PASSWORD` and pass them to `terraform apply` command as shown in the [Quickstart guide](./quickstart.md#setup-terraform-variables).

```
rhel_subscription_username  = "user@test.com"
rhel_subscription_password  = "mypassword"
```
Or define following variables to use activation key for RHEL subscription:
```
rhel_subscription_org = "org-id"
rhel_subscription_activationkey = "activation-key"
```

These variables specifies the OpenShift cluster domain details.
Edit it as per your requirements.
```
cluster_domain              = "nip.io"
cluster_id_prefix           = "ceph"
cluster_id                  = ""
```
Set the `cluster_domain` to `nip.io`, `xip.io` or `sslip.io` if you prefer using online wildcard domains.
Default is `nip.io`.
The `cluster_id_prefix` should not be more than 8 characters. Nodes are pre-fixed with this value.
Default value is `ceph`
If `cluster_if_prefix` is not set, the `cluster_id` will be used only without prefix.

A random value will be used for `cluster_id` if not set.
The total length of `cluster_id_prefix`.`cluster_id` should not exceed 14 characters.



The following variable is used to set the network adapter type for the VMs. By default the VMs will use SEA. If SRIOV is required then uncomment the variable
```
network_type                = "SRIOV"
```

The following variable is used to define the amount of SR-IOV Virtual Functions used for VNIC failover of the network adapter for the VMs. By default the VMs will use 1, which defines `no VNIC failover`. Any setting higher then 1 creates additional virtual functions and configures them in a VNIC failover setup. `Be aware of the fact, that RHCOS and some Linux releases might not handle VNIC failover with more then 2 SR-IOV Virtual Functions properly. The recommended value is 2 for VNIC failover.`
Valid options are: Any number supported for VNIC failover from 1 to 6
```
sriov_vnic_failover_vfs                = 1
```

The following variable is used to define the capacity of SR-IOV Logical Ports of the 1st network adapter for the VMs. By default the VMs will use 2%.
Valid options are: Any number which can be devided by 2 and results in an integer. 100% = 1.0; 80% = 0.80; 60% = 0.60; etc
```
sriov_capacity                = 0.02
```

The following variable is used to specify the PowerVC [Storage Connectivity Group](https://www.ibm.com/support/knowledgecenter/SSVSPA_1.4.4/com.ibm.powervc.cloud.help.doc/powervc_storage_connectivity_groups_cloud.html) (SCG). Empty value will use the default SCG
```
scg_id                      = ""
```
This variable determines the visibility of a dynamically created compute template (flavor) in Terraform when `scg_id` is specified. By default, its value is set to `false` meaning the compute template remains private and is not displayed in the UI.
```

scg_flavor_is_public  = false
```

This variable specifies the external DNS servers to forward DNS queries that cannot be resolved locally.
```
dns_forwarders              = "1.1.1.1; 9.9.9.9"
```


These are NTP specific variables that are used for time-synchronization in the OpenShift cluster.
```
chrony_config               = true
chrony_config_servers       = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]
```