resource "aws_key_pair" "sshkeypair" {
  key_name   = "sshkeypair"
  public_key = file("~/.ssh/id_rsa.pub")
}