init:
	terraform init -backend-config=s3_backend_configuration.conf 
plan:
	terraform plan -var-file="example.auto.tfvars" -var-file="secrets.tfvars"
apply:
	terraform apply -var-file="example.auto.tfvars" -var-file="secrets.tfvars"
destroy:
	terraform destroy -var-file="example.auto.tfvars" -var-file="secrets.tfvars"
