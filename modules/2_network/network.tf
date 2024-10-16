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

data "openstack_networking_network_v2" "network" {
  name = var.network_name
}

data "openstack_networking_subnet_v2" "subnet" {
  network_id = data.openstack_networking_network_v2.network.id
}

resource "openstack_networking_port_v2" "ceph_vip" {
  count = local.ceph_count > 1 ? 1 : 0

  name           = "${var.cluster_id}-ceph-vip"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = local.fixed_ip_v4
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

resource "openstack_networking_port_v2" "ceph_port" {
  count      = local.ceph_count
  depends_on = [openstack_networking_port_v2.ceph_vip]

  name           = "${var.cluster_id}-ceph-port-${count.index}"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = local.ceph_count == 1 ? local.fixed_ip_v4 : (length(local.ceph_ips) == 0 ? "" : local.ceph_ips[count.index])
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

locals {
  sriov    = <<EOF
   {
       "delete_with_instance": 1,
       "vnic_required_vfs": ${var.sriov_vnic_failover_vfs},
       "capacity": ${var.sriov_capacity},
       "vlan_type": "allowed"
   }
   EOF
  bindings = var.network_type == "SRIOV" ? [{ vnic_type = "direct", profile = local.sriov }] : []

  ceph_count   = lookup(var.ceph, "count", 1)
  fixed_ip_v4     = lookup(var.ceph, "fixed_ip_v4", "")
  ceph_ips     = lookup(var.ceph, "fixed_ips", [])
}
