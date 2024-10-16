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

locals {
  ceph_count = lookup(var.ceph, "count", 1)
}

resource "openstack_compute_keypair_v2" "key-pair" {
  count      = var.create_keypair
  name       = var.keypair_name
  public_key = var.public_key
}

resource "random_id" "label" {
  count       = var.scg_id == "" ? 0 : 1
  byte_length = "2"
}

resource "openstack_compute_flavor_v2" "ceph_scg" {
  count        = var.scg_id == "" ? 0 : 1
  name         = "${var.ceph["instance_type"]}-${random_id.label[0].hex}-scg"
  region       = data.openstack_compute_flavor_v2.ceph.region
  ram          = data.openstack_compute_flavor_v2.ceph.ram
  vcpus        = data.openstack_compute_flavor_v2.ceph.vcpus
  disk         = data.openstack_compute_flavor_v2.ceph.disk
  swap         = data.openstack_compute_flavor_v2.ceph.swap
  rx_tx_factor = data.openstack_compute_flavor_v2.ceph.rx_tx_factor
  is_public    = var.scg_flavor_is_public
  extra_specs  = merge(data.openstack_compute_flavor_v2.ceph.extra_specs, { "powervm:storage_connectivity_group" : var.scg_id })
}

data "openstack_compute_flavor_v2" "ceph" {
  name = var.ceph["instance_type"]
}

resource "openstack_compute_instance_v2" "ceph" {
  count = local.ceph_count

  name      = "${var.cluster_id}-ceph-node-${count.index}"
  image_id  = var.ceph["image_id"]
  flavor_id = var.scg_id == "" ? data.openstack_compute_flavor_v2.ceph.id : openstack_compute_flavor_v2.ceph_scg[0].id
  key_pair  = openstack_compute_keypair_v2.key-pair.0.name
  network {
    port = var.ceph_port_ids[count.index]
  }
  availability_zone = lookup(var.ceph, "availability_zone", var.openstack_availability_zone)
}

resource "null_resource" "ceph_init" {
  count      = local.ceph_count


  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
  provisioner "remote-exec" {
    inline = [
      "whoami"
    ]
  }
  provisioner "file" {
    content     = var.private_key
    destination = ".ssh/id_rsa"
  }
  provisioner "file" {
    content     = var.public_key
    destination = ".ssh/id_rsa.pub"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo chmod 600 .ssh/id_rsa*",
      "sudo sed -i.bak -e 's/^ - set_hostname/# - set_hostname/' -e 's/^ - update_hostname/# - update_hostname/' /etc/cloud/cloud.cfg",
      "sudo hostnamectl set-hostname --static ${lower(var.cluster_id)}-node-${count.index}.${lower(var.cluster_id)}.${var.cluster_domain}",
      "echo 'HOSTNAME=${lower(var.cluster_id)}-node-${count.index}.${lower(var.cluster_id)}.${var.cluster_domain}' | sudo tee -a /etc/sysconfig/network > /dev/null",
      "sudo hostname -F /etc/hostname",
      "echo 'vm.max_map_count = 262144' | sudo tee --append /etc/sysctl.conf > /dev/null",
      "dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm",
    ]
  }
}

resource "null_resource" "ceph_init_etc_hosts" {
  depends_on = [null_resource.ceph_init]
  count      = local.ceph_count


  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
  provisioner "remote-exec" {
    inline = [
      "whoami"
    ]
  }

  provisioner "remote-exec" {
    inline = [<<EOT
        %{ for i in range(local.ceph_count) }
          echo "${openstack_compute_instance_v2.ceph[i].access_ip_v4} ${lower(var.cluster_id)}-node-${i}.${lower(var.cluster_id)}.${var.cluster_domain} ${lower(var.cluster_id)}-node-${i}" >> /etc/hosts
        %{ endfor }
        EOT
    ]
  }
}

resource "null_resource" "ceph_register" {
  count      = (var.rhel_subscription_username == "" || var.rhel_subscription_username == "<subscription-id>") && var.rhel_subscription_org == "" ? 0 : local.ceph_count
  depends_on = [null_resource.ceph_init]
  triggers = {
    ceph_ip         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    rhel_username      = var.rhel_username
    private_key        = var.private_key
    ssh_agent          = var.ssh_agent
    
    connection_timeout = var.connection_timeout
  }

  connection {
    type         = "ssh"
    user         = self.triggers.rhel_username
    host         = self.triggers.ceph_ip
    private_key  = self.triggers.private_key
    agent        = self.triggers.ssh_agent
    timeout      = "${self.triggers.connection_timeout}m"
    
  }

  provisioner "remote-exec" {
    inline = [<<EOF

# Give some more time to subscription-manager
sudo subscription-manager config --server.server_timeout=600
sudo subscription-manager clean
if [[ '${var.rhel_subscription_org}' == '' ]]; then
    sudo subscription-manager register --username='${var.rhel_subscription_username}' --password='${var.rhel_subscription_password}' --force
else
    sudo subscription-manager register --org='${var.rhel_subscription_org}' --activationkey='${var.rhel_subscription_activationkey}' --force
fi
sudo subscription-manager refresh
sudo subscription-manager attach --auto

EOF
    ]
  }
  # Delete Terraform files as contains sensitive data
  provisioner "remote-exec" {
    inline = [
      "sudo rm -rf /tmp/terraform_*"
    ]
  }

  provisioner "remote-exec" {
    connection {
      type         = "ssh"
      user         = self.triggers.rhel_username
      host         = self.triggers.ceph_ip
      private_key  = self.triggers.private_key
      agent        = self.triggers.ssh_agent
      timeout      = "${self.triggers.connection_timeout}m"
      
    }

    when       = destroy
    on_failure = continue
    inline = [
      "sudo subscription-manager unregister",
      "sudo subscription-manager remove --all",
    ]
  }
}

resource "null_resource" "enable_repos" {
  count      = local.ceph_count
  depends_on = [null_resource.ceph_init, null_resource.ceph_register]

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
  }

  provisioner "remote-exec" {
    inline = [<<EOF
# Additional repo for installing ansible package
if ( [[ -z "${var.rhel_subscription_username}" ]] || [[ "${var.rhel_subscription_username}" == "<subscription-id>" ]] ) && [[ -z "${var.rhel_subscription_org}" ]]; then
  sudo yum install -y epel-release
  sudo yum install -y ansible
elif [[ "$(printf '%s\n' "8.5" "$(cat /etc/redhat-release | sed 's/[^0-9.]*//g')" | sort -V | head -n1)" == "8.5" ]]; then
  # Compared release version with 8.5 (eg: 8.10 > 8.5)
  sudo yum install -y ansible-core
else
  sudo subscription-manager repos --enable ${var.highavailability_repo}
  sudo subscription-manager repos --enable ${var.codeready_builder_repo}
  sudo subscription-manager repos --enable ${var.baseos_repo}
  sudo subscription-manager repos --enable ${var.appstream_repo}
  sudo subscription-manager repos --enable ${var.supplementary_repo}
fi
EOF
    ]
  }
  provisioner "remote-exec" {
    inline = [
      "cat << EOF > /etc/yum.repos.d/ceph.repo",
      "[ceph]",
      "baseurl=${var.ceph_repo}",
      "enabled=1",
      "gpgcheck=0",
      "countme=1",
      "EOF",
    ]
  }
}

resource "null_resource" "ceph_packages" {
  count      = local.ceph_count
  depends_on = [ null_resource.enable_repos]

  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum update -y --skip-broken",
      "sudo yum install -y wget jq git net-tools vim python3 tar tmux",
      "dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm",
      "dnf install -y ceph",
    ]
  }
  provisioner "remote-exec" {
    inline = [
      "sudo systemctl unmask NetworkManager",
      "sudo systemctl start NetworkManager",
      "for i in $(nmcli device | grep unmanaged | awk '{print $1}'); do echo NM_CONTROLLED=yes | sudo tee -a /etc/sysconfig/network-scripts/ifcfg-$i; done",
      "sudo systemctl restart NetworkManager",
      "sudo systemctl enable NetworkManager",
    ]
  }
}

resource "null_resource" "ceph_reboot" {
  count      = local.ceph_count
  depends_on = [null_resource.ceph_packages, null_resource.ceph_init, null_resource.enable_repos ]

  provisioner "remote-exec" {
    inline = [
      "if [ ! -f /var/tmp/rebooted ]; then touch /var/tmp/rebooted; sudo reboot;  fi"
    ]

    connection {
      type         = "ssh"
      user         = var.rhel_username
      host         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
      private_key  = var.private_key
      agent        = var.ssh_agent
      timeout      = "${var.connection_timeout}m"
    }
  }

  triggers = {
    always_run = "${timestamp()}"
  }
}


resource "null_resource" "wait_for_ceph_reboot" {
  count      = local.ceph_count
  depends_on = [null_resource.ceph_reboot ]

  provisioner "local-exec" {
    command = <<EOT
      echo "Waiting for instance ${openstack_compute_instance_v2.ceph[count.index].access_ip_v4} to reboot"
      while ! nc -z ${openstack_compute_instance_v2.ceph[count.index].access_ip_v4} 22; do
        echo "Waiting for SSH to become available..."
        sleep 10
      done
      echo "Instance ${openstack_compute_instance_v2.ceph[count.index].access_ip_v4} is back online"
    EOT
  }

}

resource "null_resource" "ceph_config" {
  depends_on = [null_resource.ceph_init, null_resource.ceph_packages, null_resource.enable_repos, null_resource.setup_ceph_disk, null_resource.wait_for_ceph_reboot]


  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[0].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
  provisioner "remote-exec" {
    inline = [
      "whoami"
    ]
  }
  provisioner "remote-exec" {
    inline = [
      "cat << EOF > /etc/ceph/ceph.conf",
          "[global]",
          "cluster network = $(ip route | awk '{print $1}'| tail -n 1)",
          "public network = $(ip route | awk '{print $1}'| tail -n 1)",
          "fsid = $(uuidgen)",
          "mon host = $(hostname -i)",
          "mon initial members = ${lower(var.cluster_id)}-node-0",
          "osd pool default crush rule = -1",
          "[mon.${lower(var.cluster_id)}-node-0]",
          "host = ${lower(var.cluster_id)}-node-0",
          "mon addr = $(hostname -i)",
          "mon allow pool delete = true",
      "EOF",
    ]
  }
}

resource "null_resource" "ceph_ceph_init" {
  depends_on = [null_resource.ceph_config, null_resource.setup_ceph_disk, null_resource.wait_for_ceph_reboot]

  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[0].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
  provisioner "remote-exec" {
    inline = [
      "whoami"
    ]
  }
  provisioner "remote-exec" {
    inline = [

      "ceph-authtool --create-keyring /etc/ceph/ceph.mon.keyring --gen-key -n mon. --cap mon 'allow *'",
      "ceph-authtool --create-keyring /etc/ceph/ceph.client.admin.keyring --gen-key -n client.admin --cap mon 'allow *' --cap osd 'allow *' --cap mds 'allow *' --cap mgr 'allow *'",
      "ceph-authtool --create-keyring /var/lib/ceph/bootstrap-osd/ceph.keyring --gen-key -n client.bootstrap-osd --cap mon 'profile bootstrap-osd' --cap mgr 'allow r'",
      "ceph-authtool /etc/ceph/ceph.mon.keyring --import-keyring /etc/ceph/ceph.client.admin.keyring",
      "ceph-authtool /etc/ceph/ceph.mon.keyring --import-keyring /var/lib/ceph/bootstrap-osd/ceph.keyring",
      "FSID=$(grep 'fsid' /etc/ceph/ceph.conf | awk {'print $NF'})",
      "NODENAME=$(grep 'mon initial' /etc/ceph/ceph.conf | awk {'print $NF'})",
      "NODEIP=$(grep '^mon host' /etc/ceph/ceph.conf | awk {'print $NF'})",
      "monmaptool --create --add $NODENAME $NODEIP --fsid $FSID /etc/ceph/monmap",
      "mkdir /var/lib/ceph/mon/ceph-${lower(var.cluster_id)}-node-0",
      "ceph-mon --cluster ceph --mkfs -i $NODENAME --monmap /etc/ceph/monmap --keyring /etc/ceph/ceph.mon.keyring",
      "chown ceph:ceph /etc/ceph/ceph.*",
      "chown -R ceph:ceph /var/lib/ceph/mon/ceph-${lower(var.cluster_id)}-node-0 /var/lib/ceph/bootstrap-osd",
      "systemctl enable --now ceph-mon@$NODENAME",
      "ceph mon enable-msgr2",
      "ceph config set mon auth_allow_insecure_global_id_reclaim false",
      "ceph mgr module enable pg_autoscaler",
      "mkdir /var/lib/ceph/mgr/ceph-${lower(var.cluster_id)}-node-0",
      "ceph auth get-or-create mgr.$NODENAME mon 'allow profile mgr' osd 'allow *' mds 'allow *'",
      "ceph auth get-or-create mgr.${lower(var.cluster_id)}-node-0 > /etc/ceph/ceph.mgr.admin.keyring",
      "cp /etc/ceph/ceph.mgr.admin.keyring /var/lib/ceph/mgr/ceph-${lower(var.cluster_id)}-node-0/keyring",
      "chown ceph:ceph /etc/ceph/ceph.mgr.admin.keyring",
      "chown -R ceph:ceph /var/lib/ceph/mgr/ceph-${lower(var.cluster_id)}-node-0",
      "systemctl enable --now ceph-mgr@$NODENAME",
      "cat << EOF > cephmon.te",
      "# create new",
      "module cephmon 1.0;",
      "require {",
      "        type ceph_t;",
      "        type ptmx_t;",
      "        type initrc_var_run_t;",
      "        type sudo_exec_t;",
      "        type chkpwd_exec_t;",
      "        type shadow_t;",
      "        class file { execute execute_no_trans lock getattr map open read };",
      "        class capability { audit_write sys_resource };",
      "        class process setrlimit;",
      "        class netlink_audit_socket { create nlmsg_relay };",
      "        class chr_file getattr;",
      "}",
      "#============= ceph_t ==============",
      "allow ceph_t initrc_var_run_t:file { lock open read };",
      "allow ceph_t self:capability { audit_write sys_resource };",
      "allow ceph_t self:netlink_audit_socket { create nlmsg_relay };",
      "allow ceph_t self:process setrlimit;",
      "allow ceph_t sudo_exec_t:file { execute execute_no_trans open read map };",
      "allow ceph_t ptmx_t:chr_file getattr;",
      "allow ceph_t chkpwd_exec_t:file { execute execute_no_trans open read map };",
      "allow ceph_t shadow_t:file { getattr open read };",
      "EOF",
      "checkmodule -m -M -o cephmon.mod cephmon.te",
      "semodule_package --outfile cephmon.pp --module cephmon.mod",
      "semodule -i cephmon.pp",
      "#firewall-cmd --add-service=ceph-mon",
      "#firewall-cmd --runtime-to-permanent",
      "ceph -s",

    ]
  }
}

resource "null_resource" "scp_ceph_config_1" {
  depends_on = [null_resource.ceph_ceph_init, null_resource.setup_ceph_disk, null_resource.wait_for_ceph_reboot]
  count = local.ceph_count - 1
  provisioner "remote-exec" {
    inline = [
      "scp  -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa /etc/ceph/ceph.conf ${var.rhel_username}@${openstack_compute_instance_v2.ceph[count.index + 1].access_ip_v4}:/etc/ceph/ceph.conf",
      "scp  -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa /etc/ceph/ceph.client.admin.keyring ${var.rhel_username}@${openstack_compute_instance_v2.ceph[count.index + 1].access_ip_v4}:/etc/ceph/",
      "scp  -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa /var/lib/ceph/bootstrap-osd/ceph.keyring ${var.rhel_username}@${openstack_compute_instance_v2.ceph[count.index + 1].access_ip_v4}:/var/lib/ceph/bootstrap-osd/",
      "chown ceph:ceph /etc/ceph/ceph.* /var/lib/ceph/bootstrap-osd/*",
    ]
  }
  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[0].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
}

resource "null_resource" "scp_ceph_config_2" {
  depends_on = [null_resource.scp_ceph_config_1,null_resource.ceph_reboot, null_resource.setup_ceph_disk]
#  count      = local.ceph_count
  provisioner "remote-exec" {
    inline = [
      <<EOT
        %{ for i in range(local.ceph_count) }
          ssh -o StrictHostKeyChecking=no  -i ~/.ssh/id_rsa root@${openstack_compute_instance_v2.ceph[i].access_ip_v4} "ceph-volume raw prepare --data /dev/${local.disk_config.disk_name}"
          sleep 30
          ssh -o StrictHostKeyChecking=no  -i ~/.ssh/id_rsa root@${openstack_compute_instance_v2.ceph[i].access_ip_v4} "systemctl start ceph-osd@${i}.service"
          sleep 30
        %{ endfor }
        EOT
    ]


    connection {
      type         = "ssh"
      user         = var.rhel_username
      host         = openstack_compute_instance_v2.ceph[0].access_ip_v4
      private_key  = var.private_key
      agent        = var.ssh_agent
      timeout      = "${var.connection_timeout}m"
     
    }
  }
}

resource "null_resource" "ceph_filesystem" {
  depends_on = [null_resource.scp_ceph_config_2, null_resource.setup_ceph_disk]
  count = local.ceph_count
  provisioner "remote-exec" {
    inline = [
      "mkdir -p /var/lib/ceph/mds/ceph-${lower(var.cluster_id)}-node-0",
      "ceph-authtool --create-keyring /var/lib/ceph/mds/ceph-${lower(var.cluster_id)}-node-0/keyring --gen-key -n mds.${lower(var.cluster_id)}-node-0",
      "chown -R ceph:ceph /var/lib/ceph/mds/ceph-${lower(var.cluster_id)}-node-0",
      "ceph auth add mds.${lower(var.cluster_id)}-node-0 osd 'allow rwx' mds 'allow' mon 'allow profile mds' -i /var/lib/ceph/mds/ceph-${lower(var.cluster_id)}-node-0/keyring",
      "systemctl enable --now ceph-mds@${lower(var.cluster_id)}-node-0",
      "ceph osd pool create cephfs_data 32",
      "ceph osd pool create cephfs_metadata 32",
      "ceph fs new cephfs cephfs_metadata cephfs_data",
      "ceph fs ls",
      "ceph mds stat",
      "ceph fs status cephfs",

    ]
  }
  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
}

resource "null_resource" "ceph_rdb" {
  depends_on = [null_resource.scp_ceph_config_2, null_resource.setup_ceph_disk]
  count = local.ceph_count
  provisioner "remote-exec" {
    inline = [
      "ceph osd pool create rbd 32",
      "ceph osd pool set rbd pg_autoscale_mode on",
      "rbd pool init rbd",
      "rbd create --size 10G --pool rbd rbd01",
      "rbd ls -l",
    ]

    connection {
      type         = "ssh"
      user         = var.rhel_username
      host         = openstack_compute_instance_v2.ceph[0].access_ip_v4
      private_key  = var.private_key
      agent        = var.ssh_agent
      timeout      = "${var.connection_timeout}m"
     
    }
  }
}


locals {
  ceph = {
    volume_count = lookup(var.ceph, "data_volume_count", 0),
    volume_size  = lookup(var.ceph, "data_volume_size", 0)
  }
}


resource "openstack_blockstorage_volume_v3" "ceph" {
  depends_on = [openstack_compute_instance_v2.ceph]
  count      = local.ceph.volume_count * var.ceph["count"]
  name       = "${var.cluster_id}-ceph-${count.index}-volume"
  size       = local.ceph.volume_size
}

resource "openstack_compute_volume_attach_v2" "ceph" {
  count       = local.ceph.volume_count * var.ceph["count"]
  instance_id = openstack_compute_instance_v2.ceph.*.id[floor(count.index / local.ceph.volume_count)]
  volume_id   = openstack_blockstorage_volume_v3.ceph.*.id[count.index]
}

locals {
  disk_config = {
    volume_size = local.ceph.volume_size
    disk_name   = "disk/pv-storage-disk"
  }
  storage_path = "/export"
}

resource "null_resource" "setup_ceph_disk" {
  count       = local.ceph.volume_count * var.ceph["count"]
  depends_on = [openstack_compute_volume_attach_v2.ceph,null_resource.ceph_reboot, null_resource.wait_for_ceph_reboot]

  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = openstack_compute_instance_v2.ceph[count.index].access_ip_v4
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
   
  }
  provisioner "file" {
    content     = templatefile("${path.module}/templates/create_disk_link.sh", local.disk_config)
    destination = "/tmp/create_disk_link.sh"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo rm -rf mkdir ${local.storage_path}; sudo mkdir -p ${local.storage_path}; sudo chmod -R 755 ${local.storage_path}",
      "sudo chmod +x /tmp/create_disk_link.sh",
      # Fix for copying file from Windows OS having CR,
      "sudo sed -i 's/\r//g' /tmp/create_disk_link.sh",
      "sudo /tmp/create_disk_link.sh",
      "sudo dd if=/dev/zero of=/dev/${local.disk_config.disk_name} bs=10M count=10",
    ]
  }
}
