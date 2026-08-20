terraform {
  required_version = ">= 1.5"
  backend "s3" {
    bucket = "state"
    encrypt = true
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

variable "env" {
  type = string
}
