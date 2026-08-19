resource "aws_security_group" "allow_all" {
  name = "allow_all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}

resource "aws_iam_policy" "admin" {
  name = "admin-policy"
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "*"
      Effect   = "Allow"
    }]
  })
}
