
resource "aws_security_group" "servers_sg" {

  name        = "ServersSG"
  description = "Allow SSH y HTTP inbound traffic"
  vpc_id      = "vpc-0d5e7085df1c070c3"

  tags = {
    Name = "Server SG"
  }

}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh" {

  security_group_id = aws_security_group.servers_sg.id
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "Allow SSH"
  }

}

resource "aws_vpc_security_group_ingress_rule" "allow_http" {

  security_group_id = aws_security_group.servers_sg.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "Allow HTTP"
  }

}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic" {
  security_group_id = aws_security_group.servers_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # all ports
}

