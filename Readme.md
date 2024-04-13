# Introducción a Terraform

## Instalación de Terraform CLI
(Actualización: abril 2024)

Desde la página de downloads de terraform (https://www.terraform.io/downloads.html) descarga la versión adecuada para tu sistema operativo
(descargaremos aquí la versión para Linux 64 bits)

```
$ wget https://releases.hashicorp.com/terraform/1.8.0/terraform_1.8.0_linux_amd64.zip

``` 

Descomprime el fichero usando unzip (si lo necesitas instala el paquete unzip):

```
$ sudo apt install unzip

$ unzip terraform_1.8.0_linux_amd64.zip
```

Mueve el fichero terraform ha una carpeta incluida en el PATH, por ejemplo a /usr/local/bin/:

```
$ sudo mv terraform /usr/local/bin
```

Prueba la instalación con:

```
$ terraform -version
Terraform v1.8.0
on linux_amd64
```

## Comandos Terraform

Muestra la ayuda sobre los comandos disponibles con:

```
$ terraform -help
Usage: terraform [global options] <subcommand> [args]

The available commands for execution are listed below.
The primary workflow commands are given first, followed by
less common or more advanced commands.

Main commands:
  init          Prepare your working directory for other commands
  validate      Check whether the configuration is valid
  plan          Show changes required by the current configuration
  apply         Create or update infrastructure
  destroy       Destroy previously-created infrastructure

All other commands:
  console       Try Terraform expressions at an interactive command prompt
  fmt           Reformat your configuration in the standard style
  force-unlock  Release a stuck lock on the current workspace
  get           Install or upgrade remote Terraform modules
  graph         Generate a Graphviz graph of the steps in an operation
  import        Associate existing infrastructure with a Terraform resource
  login         Obtain and save credentials for a remote host
  logout        Remove locally-stored credentials for a remote host
  metadata      Metadata related commands
  output        Show output values from your root module
  providers     Show the providers required for this configuration
  refresh       Update the state to match remote systems
  show          Show the current state or a saved plan
  state         Advanced state management
  taint         Mark a resource instance as not fully functional
  test          Execute integration tests for Terraform modules
  untaint       Remove the 'tainted' state from a resource instance
  version       Show the current Terraform version
  workspace     Workspace management

Global options (use these before the subcommand, if any):
  -chdir=DIR    Switch to a different working directory before executing the
                given subcommand.
  -help         Show this help output, or the help for a specified subcommand.
  -version      An alias for the "version" subcommand.
```

O la ayuda de un subcomando específico:

```
$ terraform -help plan
Usage: terraform [global options] plan [options]

  Generates a speculative execution plan, showing what actions Terraform
  would take to apply the current configuration. This command will not
  actually perform the planned actions.

  You can optionally save the plan to a file, which you can then pass to
  the "apply" command to perform exactly the actions described in the plan.

Plan Customization Options:
...
```

## Aspectos básicos. Documentación

La infracestructura con Terraform se crea mediante un conjunto de ficheros (.tf),
llamados ficheros de configuración, que incluyen: identificación del proveedor o proveedores,
creación de recursos, definición de variables, uso de datos, outputs, etc.

### Lenguaje Terraform 

```
<BLOCK TYPE> "<BLOCK LABEL>" "<BLOCK LABEL>" {
  # Block body
  <IDENTIFIER> = <EXPRESSION> # Argument
    ...
  <IDENTIFIER> = <EXPRESSION> # Argument
}
```

### Flujo de Trabajo (Workflow)

1.- Creación de los fichero .tf

    - providers

    - resources

    - datasources

    - variables

    - outputs, etc.
    
2.- Terraform init

3.- Terraform fmt

4.- Terraform validate

5.- Terraform plan

6.- Terraform apply

7.- Terraform destroy

### Tutoriales

https://developer.hashicorp.com/terraform/tutorials

### Proveedores
https://www.terraform.io/docs/providers/index.html

Puedes obtener información sobre los proveedores en:

https://registry.terraform.io/browse/providers

Dentro de cada proveedor puedes consultar la documentación para crear los recursos disponibles:

Para AWS: https://www.terraform.io/docs/providers/aws/index.html

Para GCP: https://www.terraform.io/docs/providers/google/index.html

En la documentacióm para cada proveedor, tenemos los "Data sources" con la información
que nos ofrece el proveedor y los "Resources" con los parámetros y los atributos para crearlos.


Puedes consultar más información sobre otros elementos:

Variables: https://www.terraform.io/docs/configuration/variables.html

Outputs: https://www.terraform.io/docs/configuration/outputs.html

Funciones: https://www.terraform.io/docs/configuration/functions.html

Provisioners: https://developer.hashicorp.com/terraform/language/resources/provisioners/syntax

Módulos: https://www.terraform.io/docs/configuration/modules.html


## Ejemplo

En el siguiente ejemplo usaremos AWS:

### Asignando el proveedor

```
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.44.0"
    }
  }
}

# Authentication and Configuration of the AWS Provider

provider "aws" {
  region     = "us-east-1"
  
  # ~/.aws/credentials
  profile = "default"

  # Alternativamente, aunque desaconsejado, se pueden incluir los valores aquí
  # access_key = "ACCESSKEY"
  # secret_key = "SECRETKEY"
  # token      = "SESSIONTOKEN"
}
```


### Crear una SSH key pair 

```
resource "aws_key_pair" "sshkeypair" {
  key_name   = "sshkeypair"
  public_key = file("~/.ssh/id_rsa.pub")
}
```

### Crear una grupo de seguridad

Este grupo de seguridad permite tráfico SSH y HTTP de entrada y todo el de salida

```

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

```
### Crear una instancia 

Esta instancia tendrá la SSH Key Pair y el grupo de seguridad creados anteriormente

```
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

```

## Iniciar Terraform

Antes de utilizar terraform es necesario inicializarlo para que se descargue lo necesario
para trabajar con los proveedores y elementos definidos en los ficheros de configuración (.tf)

```
$ terraform init

Initializing the backend...

Initializing provider plugins...
- Finding hashicorp/aws versions matching "5.44.0"...
- Installing hashicorp/aws v5.44.0...
- Installed hashicorp/aws v5.44.0 (signed by HashiCorp)

Terraform has created a lock file .terraform.lock.hcl to record the provider
selections it made above. Include this file in your version control repository
so that Terraform can guarantee to make the same selections by default when
you run "terraform init" in the future.

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.

```


## Planear la infraestructura

```
$ terraform plan

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_instance.web will be created
  + resource "aws_instance" "web" {
      + ami                                  = "ami-051f8a213df8bc089"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = (known after apply)
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_stop                     = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + host_resource_group_arn              = (known after apply)
      + iam_instance_profile                 = (known after apply)
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_lifecycle                   = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.micro"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "sshkeypair"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = [
          + "ServersSG",
        ]
      + source_dest_check                    = true
      + spot_instance_request_id             = (known after apply)
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Name" = "Server"
        }
      + tags_all                             = {
          + "Name" = "Server"
        }
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + user_data_replace_on_change          = false
      + vpc_security_group_ids               = (known after apply)
    }

  # aws_key_pair.sshkeypair will be created
  + resource "aws_key_pair" "sshkeypair" {
      + arn             = (known after apply)
      + fingerprint     = (known after apply)
      + id              = (known after apply)
      + key_name        = "sshkeypair"
      + key_name_prefix = (known after apply)
      + key_pair_id     = (known after apply)
      + key_type        = (known after apply)
      + public_key      = "ssh-rsa AAAA...ZiMQVTW= user@host"
      + tags_all        = (known after apply)
    }

  # aws_security_group.servers_sg will be created
  + resource "aws_security_group" "servers_sg" {
      + arn                    = (known after apply)
      + description            = "Allow SSH y HTTP inbound traffic"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = "ServersSG"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "Server SG"
        }
      + tags_all               = {
          + "Name" = "Server SG"
        }
      + vpc_id                 = "vpc-0d5e7085df1c070c3"
    }

  # aws_vpc_security_group_egress_rule.allow_all_traffic will be created
  + resource "aws_vpc_security_group_egress_rule" "allow_all_traffic" {
      + arn                    = (known after apply)
      + cidr_ipv4              = "0.0.0.0/0"
      + id                     = (known after apply)
      + ip_protocol            = "-1"
      + security_group_id      = (known after apply)
      + security_group_rule_id = (known after apply)
      + tags_all               = {}
    }

  # aws_vpc_security_group_ingress_rule.allow_http will be created
  + resource "aws_vpc_security_group_ingress_rule" "allow_http" {
      + arn                    = (known after apply)
      + cidr_ipv4              = "0.0.0.0/0"
      + from_port              = 80
      + id                     = (known after apply)
      + ip_protocol            = "tcp"
      + security_group_id      = (known after apply)
      + security_group_rule_id = (known after apply)
      + tags                   = {
          + "Name" = "Allow HTTP"
        }
      + tags_all               = {
          + "Name" = "Allow HTTP"
        }
      + to_port                = 80
    }

  # aws_vpc_security_group_ingress_rule.allow_ssh will be created
  + resource "aws_vpc_security_group_ingress_rule" "allow_ssh" {
      + arn                    = (known after apply)
      + cidr_ipv4              = "0.0.0.0/0"
      + from_port              = 22
      + id                     = (known after apply)
      + ip_protocol            = "tcp"
      + security_group_id      = (known after apply)
      + security_group_rule_id = (known after apply)
      + tags                   = {
          + "Name" = "Allow SSH"
        }
      + tags_all               = {
          + "Name" = "Allow SSH"
        }
      + to_port                = 22
    }

Plan: 6 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + show_server_ip = (known after apply)

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Note: You didn't use the -out option to save this plan, so Terraform can't guarantee to take exactly these actions if you run "terraform apply" now.

```



## Aplicar la infraestructura

```
$ terraform apply

 ... ( Vuelve a salir el Plan ) ...
 
Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_key_pair.sshkeypair: Creating...
aws_security_group.servers_sg: Creating...
aws_key_pair.sshkeypair: Creation complete after 0s [id=sshkeypair]
aws_security_group.servers_sg: Creation complete after 1s [id=sg-0a6e6aa7ddf911cdf]
aws_instance.web: Creating...
aws_vpc_security_group_ingress_rule.allow_ssh: Creating...
aws_vpc_security_group_egress_rule.allow_all_traffic: Creating...
aws_vpc_security_group_ingress_rule.allow_http: Creating...
aws_vpc_security_group_egress_rule.allow_all_traffic: Creation complete after 1s [id=sgr-05229a136b868cace]
aws_vpc_security_group_ingress_rule.allow_http: Creation complete after 1s [id=sgr-0caff5b673c9c6f28]
aws_vpc_security_group_ingress_rule.allow_ssh: Creation complete after 1s [id=sgr-0207b33f0aaba4e22]
aws_instance.web: Still creating... [10s elapsed]
aws_instance.web: Still creating... [20s elapsed]
aws_instance.web: Creation complete after 22s [id=i-0783f81729e478fe3]

Apply complete! Resources: 6 added, 0 changed, 0 destroyed.

Outputs:

show_server_ip = "55.55.55.555"


```


## Destruir la infraestructura

```
$ terraform destroy

aws_key_pair.sshkeypair: Refreshing state... [id=sshkeypair]
aws_security_group.servers_sg: Refreshing state... [id=sg-0a6e6aa7ddf911cdf]
aws_instance.web: Refreshing state... [id=i-0783f81729e478fe3]
aws_vpc_security_group_ingress_rule.allow_ssh: Refreshing state... [id=sgr-0207b33f0aaba4e22]
aws_vpc_security_group_ingress_rule.allow_http: Refreshing state... [id=sgr-0caff5b673c9c6f28]
aws_vpc_security_group_egress_rule.allow_all_traffic: Refreshing state... [id=sgr-05229a136b868cace]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  - destroy

Terraform will perform the following actions:

  # aws_instance.web will be destroyed
  - resource "aws_instance" "web" {
      - ami                                  = "ami-051f8a213df8bc089" -> null
      - arn                                  = "arn:aws:ec2:us-east-1:058264437899:instance/i-0783f81729e478fe3" -> null
      - associate_public_ip_address          = true -> null
      - availability_zone                    = "us-east-1b" -> null
      - cpu_core_count                       = 1 -> null
      - cpu_threads_per_core                 = 1 -> null
      - disable_api_stop                     = false -> null
      - disable_api_termination              = false -> null
      - ebs_optimized                        = false -> null
      - get_password_data                    = false -> null
      - hibernation                          = false -> null
      - id                                   = "i-0783f81729e478fe3" -> null
      - instance_initiated_shutdown_behavior = "stop" -> null
      - instance_state                       = "running" -> null
      - instance_type                        = "t2.micro" -> null
      - ipv6_address_count                   = 0 -> null
      - ipv6_addresses                       = [] -> null
      - key_name                             = "sshkeypair" -> null
      - monitoring                           = false -> null
      - placement_partition_number           = 0 -> null
      - primary_network_interface_id         = "eni-0e2408f7a4cacec86" -> null
      - private_dns                          = "ip-172-31-16-187.ec2.internal" -> null
      - private_ip                           = "172.31.16.187" -> null
      - public_dns                           = "ec2-54-84-65-184.compute-1.amazonaws.com" -> null
      - public_ip                            = "54.84.65.184" -> null
      - secondary_private_ips                = [] -> null
      - security_groups                      = [
          - "ServersSG",
        ] -> null
      - source_dest_check                    = true -> null
      - subnet_id                            = "subnet-09bde2c6b0f56c0cd" -> null
      - tags                                 = {
          - "Name" = "Server"
        } -> null
      - tags_all                             = {
          - "Name" = "Server"
        } -> null
      - tenancy                              = "default" -> null
      - user_data_replace_on_change          = false -> null
      - vpc_security_group_ids               = [
          - "sg-0a6e6aa7ddf911cdf",
        ] -> null
        # (7 unchanged attributes hidden)

      - capacity_reservation_specification {
          - capacity_reservation_preference = "open" -> null
        }

      - cpu_options {
          - core_count       = 1 -> null
          - threads_per_core = 1 -> null
            # (1 unchanged attribute hidden)
        }

      - credit_specification {
          - cpu_credits = "standard" -> null
        }

      - enclave_options {
          - enabled = false -> null
        }

      - maintenance_options {
          - auto_recovery = "default" -> null
        }

      - metadata_options {
          - http_endpoint               = "enabled" -> null
          - http_protocol_ipv6          = "disabled" -> null
          - http_put_response_hop_limit = 2 -> null
          - http_tokens                 = "required" -> null
          - instance_metadata_tags      = "disabled" -> null
        }

      - private_dns_name_options {
          - enable_resource_name_dns_a_record    = false -> null
          - enable_resource_name_dns_aaaa_record = false -> null
          - hostname_type                        = "ip-name" -> null
        }

      - root_block_device {
          - delete_on_termination = true -> null
          - device_name           = "/dev/xvda" -> null
          - encrypted             = false -> null
          - iops                  = 3000 -> null
          - tags                  = {} -> null
          - tags_all              = {} -> null
          - throughput            = 125 -> null
          - volume_id             = "vol-0e6f5384393da02ad" -> null
          - volume_size           = 8 -> null
          - volume_type           = "gp3" -> null
            # (1 unchanged attribute hidden)
        }
    }

  # aws_key_pair.sshkeypair will be destroyed
  - resource "aws_key_pair" "sshkeypair" {
      - arn             = "arn:aws:ec2:us-east-1:058264437899:key-pair/sshkeypair" -> null
      - fingerprint     = "20:d0:80:4c:e6:1d:84:cf:3e:de:c5:15:03:f3:65:24" -> null
      - id              = "sshkeypair" -> null
      - key_name        = "sshkeypair" -> null
      - key_pair_id     = "key-035f78404ea8c9d32" -> null
      - key_type        = "rsa" -> null
      - public_key      = "ssh-rsa AAAA...utZiMQVTWM= user@host" -> null
      - tags            = {} -> null
      - tags_all        = {} -> null
        # (1 unchanged attribute hidden)
    }

  # aws_security_group.servers_sg will be destroyed
  - resource "aws_security_group" "servers_sg" {
      - arn                    = "arn:aws:ec2:us-east-1:058264437899:security-group/sg-0a6e6aa7ddf911cdf" -> null
      - description            = "Allow SSH y HTTP inbound traffic" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
                # (1 unchanged attribute hidden)
            },
        ] -> null
      - id                     = "sg-0a6e6aa7ddf911cdf" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - from_port        = 22
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 22
                # (1 unchanged attribute hidden)
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - from_port        = 80
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 80
                # (1 unchanged attribute hidden)
            },
        ] -> null
      - name                   = "ServersSG" -> null
      - owner_id               = "058264437899" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "Server SG"
        } -> null
      - tags_all               = {
          - "Name" = "Server SG"
        } -> null
      - vpc_id                 = "vpc-0d5e7085df1c070c3" -> null
        # (1 unchanged attribute hidden)
    }

  # aws_vpc_security_group_egress_rule.allow_all_traffic will be destroyed
  - resource "aws_vpc_security_group_egress_rule" "allow_all_traffic" {
      - arn                    = "arn:aws:ec2:us-east-1:058264437899:security-group-rule/sgr-05229a136b868cace" -> null
      - cidr_ipv4              = "0.0.0.0/0" -> null
      - id                     = "sgr-05229a136b868cace" -> null
      - ip_protocol            = "-1" -> null
      - security_group_id      = "sg-0a6e6aa7ddf911cdf" -> null
      - security_group_rule_id = "sgr-05229a136b868cace" -> null
      - tags_all               = {} -> null
    }

  # aws_vpc_security_group_ingress_rule.allow_http will be destroyed
  - resource "aws_vpc_security_group_ingress_rule" "allow_http" {
      - arn                    = "arn:aws:ec2:us-east-1:058264437899:security-group-rule/sgr-0caff5b673c9c6f28" -> null
      - cidr_ipv4              = "0.0.0.0/0" -> null
      - from_port              = 80 -> null
      - id                     = "sgr-0caff5b673c9c6f28" -> null
      - ip_protocol            = "tcp" -> null
      - security_group_id      = "sg-0a6e6aa7ddf911cdf" -> null
      - security_group_rule_id = "sgr-0caff5b673c9c6f28" -> null
      - tags                   = {
          - "Name" = "Allow HTTP"
        } -> null
      - tags_all               = {
          - "Name" = "Allow HTTP"
        } -> null
      - to_port                = 80 -> null
    }

  # aws_vpc_security_group_ingress_rule.allow_ssh will be destroyed
  - resource "aws_vpc_security_group_ingress_rule" "allow_ssh" {
      - arn                    = "arn:aws:ec2:us-east-1:058264437899:security-group-rule/sgr-0207b33f0aaba4e22" -> null
      - cidr_ipv4              = "0.0.0.0/0" -> null
      - from_port              = 22 -> null
      - id                     = "sgr-0207b33f0aaba4e22" -> null
      - ip_protocol            = "tcp" -> null
      - security_group_id      = "sg-0a6e6aa7ddf911cdf" -> null
      - security_group_rule_id = "sgr-0207b33f0aaba4e22" -> null
      - tags                   = {
          - "Name" = "Allow SSH"
        } -> null
      - tags_all               = {
          - "Name" = "Allow SSH"
        } -> null
      - to_port                = 22 -> null
    }

Plan: 0 to add, 0 to change, 6 to destroy.

Changes to Outputs:
  - show_server_dns = "54.84.65.184" -> null
  - show_server_ip  = "54.84.65.184" -> null

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes

aws_instance.web: Destroying... [id=i-0783f81729e478fe3]
aws_vpc_security_group_egress_rule.allow_all_traffic: Destroying... [id=sgr-05229a136b868cace]
aws_vpc_security_group_ingress_rule.allow_http: Destroying... [id=sgr-0caff5b673c9c6f28]
aws_vpc_security_group_ingress_rule.allow_ssh: Destroying... [id=sgr-0207b33f0aaba4e22]
aws_vpc_security_group_egress_rule.allow_all_traffic: Destruction complete after 0s
aws_vpc_security_group_ingress_rule.allow_ssh: Destruction complete after 0s
aws_vpc_security_group_ingress_rule.allow_http: Destruction complete after 0s
aws_instance.web: Still destroying... [id=i-0783f81729e478fe3, 10s elapsed]
aws_instance.web: Still destroying... [id=i-0783f81729e478fe3, 20s elapsed]
aws_instance.web: Still destroying... [id=i-0783f81729e478fe3, 30s elapsed]
aws_instance.web: Still destroying... [id=i-0783f81729e478fe3, 40s elapsed]
aws_instance.web: Destruction complete after 40s
aws_key_pair.sshkeypair: Destroying... [id=sshkeypair]
aws_security_group.servers_sg: Destroying... [id=sg-0a6e6aa7ddf911cdf]
aws_key_pair.sshkeypair: Destruction complete after 0s
aws_security_group.servers_sg: Destruction complete after 0s

Destroy complete! Resources: 6 destroyed.

```
