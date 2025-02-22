
data "aws_ami" "latest-kali-linux" {
  count       = var.kali_server.kali_server == "1" ? 1 : 0
  most_recent = true
  owners      = ["679593333241"] # owned by AWS marketplace

  filter {
      name   = "name"
      values = ["kali-last-snapshot-amd64-2024*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "kali_machine" {
  count                  = var.kali_server.kali_server == "1" ? 1 : 0
  ami                    = data.aws_ami.latest-kali-linux[count.index].id
  instance_type          = "t3.large"
  key_name               = var.general.key_name
  subnet_id              = var.ec2_subnet_id
  vpc_security_group_ids = [var.vpc_security_group_ids]
  private_ip             = "10.0.1.30"
  associate_public_ip_address = true
  
  tags = {
    Name = "ar-kali-${var.general.key_name}-${var.general.attack_range_name}"
  }

  provisioner "remote-exec" {
    inline = ["echo booted"]

    connection {
      type        = "ssh"
      user        = "kali"
      host        = aws_instance.kali_machine[count.index].public_ip
      private_key = file(var.aws.private_key_path)
    }
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command = <<-EOT
      cat <<EOF > vars/kali_vars.json
      {
        "general": ${jsonencode(var.general)},
        "aws": ${jsonencode(var.aws)},
        "kali_server": ${jsonencode(var.kali_server)}
      }
      EOF
    EOT
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u kali --private-key '${var.aws.private_key_path}' -i '${self.public_ip},' kali_server.yml -e @vars/kali_vars.json"
  }

  root_block_device {
    volume_type = "gp2"
    volume_size = "50"
    delete_on_termination = "true"
  }
}

resource "aws_eip" "kali_ip" {
  count    = (var.kali_server.kali_server == "1") && (var.aws.use_elastic_ips == "1") ? 1 : 0
  instance = aws_instance.kali_machine[0].id
}
