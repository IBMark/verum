resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"
