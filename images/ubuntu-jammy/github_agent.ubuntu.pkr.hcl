packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "runner_version" {
  description = "The version (no v prefix) of the runner software to install https://github.com/actions/runner/releases. The latest release will be fetched from GitHub if not provided."
  default     = null
}

variable "region" {
  description = "The region to build the image in"
  type        = string
  default     = "eu-west-1"
}

variable "security_group_id" {
  description = "The ID of the security group Packer will associate with the builder to enable access"
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "If using VPC, the ID of the subnet, such as subnet-12345def, where Packer will launch the EC2 instance. This field is required if you are using an non-default VPC"
  type        = string
  default     = null
}

variable "associate_public_ip_address" {
  description = "If using a non-default VPC, there is no public IP address assigned to the EC2 instance. If you specified a public subnet, you probably want to set this to true. Otherwise the EC2 instance won't have access to the internet"
  type        = string
  default     = null
}

variable "instance_type" {
  description = "The instance type Packer will use for the builder"
  type        = string
  default     = "t3.medium"
}

variable "iam_instance_profile" {
  description = "IAM instance profile Packer will use for the builder. An empty string (default) means no profile will be assigned."
  type        = string
  default     = ""
}

variable "root_volume_size_gb" {
  type    = number
  default = 8
}

variable "ebs_delete_on_termination" {
  description = "Indicates whether the EBS volume is deleted on instance termination."
  type        = bool
  default     = true
}

variable "global_tags" {
  description = "Tags to apply to everything"
  type        = map(string)
  default     = {}
}

variable "ami_tags" {
  description = "Tags to apply to the AMI"
  type        = map(string)
  default     = {}
}

variable "snapshot_tags" {
  description = "Tags to apply to the snapshot"
  type        = map(string)
  default     = {}
}

variable "custom_shell_commands" {
  description = "Additional commands to run on the EC2 instance, to customize the instance, like installing packages"
  type        = list(string)
  default     = []
}

variable "runner_username" {
  description = "Name of the default user account"
  type        = string
  default     = "runner"
}

variable "temporary_security_group_source_public_ip" {
  description = "When enabled, use public IP of the host (obtained from https://checkip.amazonaws.com) as CIDR block to be authorized access to the instance, when packer is creating a temporary security group. Note: If you specify `security_group_id` then this input is ignored."
  type        = bool
  default     = false
}

data "http" github_runner_release_json {
  url = "https://api.github.com/repos/actions/runner/releases/latest"
  request_headers = {
    Accept = "application/vnd.github+json"
    X-GitHub-Api-Version : "2022-11-28"
  }
}

locals {
  runner_version = coalesce(var.runner_version, trimprefix(jsondecode(data.http.github_runner_release_json.body).tag_name, "v"))
  user_data      = <<-EOT
  #cloud-config
  system_info:
    default_user:
        name: ${var.runner_username}
  EOT
}

source "amazon-ebs" "githubrunner" {
  ami_name                                  = "github-runner-ubuntu-jammy-amd64-${formatdate("YYYYMMDDhhmm", timestamp())}"
  instance_type                             = var.instance_type
  iam_instance_profile                      = var.iam_instance_profile
  region                                    = var.region
  security_group_id                         = var.security_group_id
  subnet_id                                 = var.subnet_id
  associate_public_ip_address               = var.associate_public_ip_address
  temporary_security_group_source_public_ip = var.temporary_security_group_source_public_ip

  source_ami_filter {
    filters = {
      name                = "*ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = var.runner_username
  tags = merge(
    var.global_tags,
    var.ami_tags,
    {
      OS_Version    = "ubuntu-jammy"
      Release       = "Latest"
      Base_AMI_Name = "{{ .SourceAMIName }}"
  })
  snapshot_tags = merge(
    var.global_tags,
    var.snapshot_tags,
  )

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = "${var.root_volume_size_gb}"
    volume_type           = "gp3"
    delete_on_termination = "${var.ebs_delete_on_termination}"
  }

  user_data = local.user_data
}

build {
  name = "githubactions-runner"
  sources = [
    "source.amazon-ebs.githubrunner"
  ]
  provisioner "file" {
    content     = local.user_data
    destination = "/tmp/defaults.cfg"
  }
  provisioner "shell" {
    inline = [
      "sudo mv /tmp/defaults.cfg /etc/cloud/cloud.cfg.d/defaults.cfg"
    ]
  }
  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive"
    ]
    inline = concat([
      "sudo cloud-init status --wait",
      "printf 'APT::Acquire::Retries \"10\";\n' | sudo tee /etc/apt/apt.conf.d/80retries > /dev/null",
      "printf 'APT::Get::Assume-Yes \"true\";\n' | sudo tee /etc/apt/apt.conf.d/90forceyes > /dev/null",
      "echo 'DEBIAN_FRONTEND=noninteractive' | sudo tee /etc/environment > /dev/null",
      # Disable apt-daily upgrade services
      "sudo systemctl stop apt-daily.timer",
      "sudo systemctl disable apt-daily.timer",
      "sudo systemctl disable apt-daily.service",
      "sudo systemctl stop apt-daily-upgrade.timer",
      "sudo systemctl disable apt-daily-upgrade.timer",
      "sudo systemctl disable apt-daily-upgrade.service",
      "printf 'APT::Get::Assume-Yes \"true\";\n' | sudo tee /etc/apt/apt.conf.d/90forceyes > /dev/null",
      "sudo apt-get -y update",
      # Make sure unattended upgrades are disabled.
      "sudo apt-get purge unattended-upgrades",
      "sudo apt-get -y install ca-certificates curl gnupg lsb-release",
      "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg",
      "echo deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      "sudo add-apt-repository -y ppa:saiarcot895/chromium-beta",
      "sudo apt-get -y update",
      "sudo apt-get -y install docker-ce docker-ce-cli containerd.io jq git unzip build-essential python3-dev python3-pip python3-setuptools postgresql-client autoconf automake binutils bzip2 coreutils dnsutils gnupg2 haveged iproute2 imagemagick iputils-ping jq libc++-dev libcurl4 libgbm-dev libgconf-2-4 libgsl-dev libgtk-3-0 libmagic-dev libsqlite3-dev libtool libssl-dev lz4 net-tools netcat p7zip-full p7zip-rar parallel rsync shellcheck sqlite3 unzip xz-utils zip chromium-browser libsodium-dev pkg-config",
      # Grab libssl1.1.1 as this Ubuntu release comes with 3.0.0 which isn't always compatible.
      "wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.17_amd64.deb -P /tmp",
      "sudo dpkg -i /tmp/libssl1.1_1.1.1f-1ubuntu2.17_amd64.deb",
      "sudo systemctl enable containerd.service",
      "sudo service docker start",
      "sudo usermod -a -G docker ${var.runner_username}",
      "sudo docker pull postgres:13",
      "sudo curl -f https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb -o amazon-cloudwatch-agent.deb",
      "sudo dpkg -i amazon-cloudwatch-agent.deb",
      "sudo systemctl restart amazon-cloudwatch-agent",
      "sudo curl -f https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip",
      "unzip awscliv2.zip",
      "sudo ./aws/install",
    ], var.custom_shell_commands)
  }

  provisioner "file" {
    content = templatefile("../install-runner.sh", {
      install_runner = templatefile("../../modules/runners/templates/install-runner.sh", {
        ARM_PATCH                       = ""
        S3_LOCATION_RUNNER_DISTRIBUTION = ""
        RUNNER_ARCHITECTURE             = "x64"
      })
    })
    destination = "/tmp/install-runner.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "RUNNER_TARBALL_URL=https://github.com/actions/runner/releases/download/v${local.runner_version}/actions-runner-linux-x64-${local.runner_version}.tar.gz"
    ]
    inline = [
      "sudo chmod +x /tmp/install-runner.sh",
      "echo ${var.runner_username} | tee -a /tmp/install-user.txt",
      "sudo RUNNER_ARCHITECTURE=x64 RUNNER_TARBALL_URL=$RUNNER_TARBALL_URL /tmp/install-runner.sh",
      "echo ImageOS=ubuntu22 | tee -a /opt/actions-runner/.env"
    ]
  }

  provisioner "file" {
    content = templatefile("../start-runner.sh", {
      start_runner = templatefile("../../modules/runners/templates/start-runner.sh", { metadata_tags = "enabled" })
    })
    destination = "/tmp/start-runner.sh"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/start-runner.sh /var/lib/cloud/scripts/per-boot/start-runner.sh",
      "sudo chmod +x /var/lib/cloud/scripts/per-boot/start-runner.sh",
    ]
  }

  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
