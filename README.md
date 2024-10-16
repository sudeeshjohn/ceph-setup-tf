# **Table of Contents**
This repo cantains terraform script for deploying a ceph node on IBM Power plaform

##### Prerequisites:

1. PowerVC server
2. You need a repository where you have ceph rpms, which needs to be updated var.tfvars

##### Setup:

Update the _var.tfvars_ with PowerVC and other information and run for creating the ceph cluster.

`terraform apply -var-file var.tfvars -input=false -auto-approve -parallelism=3`

###### Destroy:

Run

`terraform destroy -var-file var.tfvars -input=false -auto-approve -parallelism=3`


