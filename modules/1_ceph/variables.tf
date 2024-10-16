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
# ©Copyright IBM Corp. 2020
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

variable "cluster_domain" {
  default = "nip.io"
}
variable "cluster_id" {
  default = "ceph"
}
variable "ceph" {}
variable "ceph_port_ids" {}
variable "ceph_repo" {}
variable "codeready_builder_repo" {}
variable "baseos_repo" {}
variable "appstream_repo" {}
variable "supplementary_repo" {}
variable "highavailability_repo" {}

variable "scg_id" {}
variable "scg_flavor_is_public" {}
variable "openstack_availability_zone" {}

variable "rhel_username" {}
variable "private_key" {}
variable "public_key" {}
variable "create_keypair" {}
variable "keypair_name" {}
variable "ssh_agent" {}
variable "connection_timeout" {}

variable "rhel_subscription_username" {}
variable "rhel_subscription_password" {}
variable "rhel_subscription_org" {}
variable "rhel_subscription_activationkey" {}
variable "ansible_repo_name" {}

variable "storage_type" {}
variable "volume_storage_template" {}

variable "fips_compliant" {}