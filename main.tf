terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.44.0"
    }
  }
}

# Authentication and Configuration of the AWS Provider

provider "aws" {
  region = "us-east-1"

  # ~/.aws/credentials
  profile = "default"

  # Alternativamente, aunque desaconsejado, se pueden incluir los valores aquí
  # access_key = "ACCESSKEY"
  # secret_key = "SECRETKEY"
  # token      = "SESSIONTOKEN"
}