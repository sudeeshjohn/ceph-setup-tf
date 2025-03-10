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

output "ceph_port_ids" {
  value = openstack_networking_port_v2.ceph_port.*.id
}

output "ceph_vip" {
  value = join("", flatten(openstack_networking_port_v2.ceph_vip.*.all_fixed_ips))
}

output "gateway_ip" {
  value = data.openstack_networking_subnet_v2.subnet.gateway_ip
}

output "cidr" {
  value = data.openstack_networking_subnet_v2.subnet.cidr
}

output "allocation_pools" {
  value = data.openstack_networking_subnet_v2.subnet.allocation_pools
}
