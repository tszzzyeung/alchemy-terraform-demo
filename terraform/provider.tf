terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
       version = "4.50.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "ap-east-1"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}