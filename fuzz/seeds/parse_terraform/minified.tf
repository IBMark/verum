resource "aws_security_group" "a" {ingress {from_port=0 to_port=65535 protocol="-1" cidr_blocks=["0.0.0.0/0"]}}
