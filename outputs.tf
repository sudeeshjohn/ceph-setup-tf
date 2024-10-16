################################################################
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Licensed Materials - Property of IBM
#
# ©Copyright IBM Corp. 2022
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

output "cluster_id" {
  value = local.cluster_id
}

output "ceph_ip" {
  value = join(", ", module.ceph.ceph_ip)
}

output "ceph_vip" {
  value = module.network.ceph_vip == "" ? null : module.network.ceph_vip
}

output "ceph_ssh_command" {
  value = "ssh -i ${var.private_key_file} ${var.rhel_username}@${module.network.ceph_vip == "" ? module.ceph.ceph_ip[0] : module.network.ceph_vip}"
}



output "etc_hosts_entries" {
  value = var.cluster_domain == "nip.io" || var.cluster_domain == "xip.io" || var.cluster_domain == "sslip.io" ? null : <<-EOF

${module.network.ceph_vip == "" ? module.ceph.ceph_ip[0] : module.network.ceph_vip} api.${local.cluster_id}.${var.cluster_domain} console-openshift-console.apps.${local.cluster_id}.${var.cluster_domain} integrated-oauth-server-openshift-authentication.apps.${local.cluster_id}.${var.cluster_domain} oauth-openshift.apps.${local.cluster_id}.${var.cluster_domain} prometheus-k8s-openshift-monitoring.apps.${local.cluster_id}.${var.cluster_domain} grafana-openshift-monitoring.apps.${local.cluster_id}.${var.cluster_domain} example.apps.${local.cluster_id}.${var.cluster_domain}
EOF
}



output "storageclass_name" {
  value = "nfs-storage-provisioner"
}

