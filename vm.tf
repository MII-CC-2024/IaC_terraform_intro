resource "aws_instance" "web" {
  ami           = "ami-051f8a213df8bc089"
  instance_type = "t2.micro"
  key_name = aws_key_pair.sshkeypair.key_name
  security_groups = [ aws_security_group.servers_sg.name ]

  tags = {
    Name = "Server"
  }
}

output "show_server_ip" {
    value = "${aws_instance.web.public_ip}"
}