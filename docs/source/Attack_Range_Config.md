# Attack Range Config

## attack_range.yml
`attack_range.yml` is the configuration file for Attack Range. Attack Range reads first the default configuration file located in `configs/attack_range_default.yml` and then the attack_range.yml (or the config which you specify with the -c parameter). The parameters in `attack_range.yml` override the parameters in `configs/attack_range_default.yml`.

## attack_range_default.yml
The `attack_range_default.yml` defines all default values for the Attack Range. The following file contains some comments to describe the different parameters:
````yml
general:
  attack_range_password: "Pl3ase-k1Ll-me:p"
  # Attack Range Master Password for all accounts in Attack Range.

  cloud_provider: "aws"
  # Cloud Provider: aws/azure/local

  key_name: "attack-range-key-pair"
  # The key name is the name of the AWS key pair and at the same time an unique identifier for Attack Ranges.

  attack_range_name: "ar"
  # Attack range Name let you build multiple Attack Ranges by changing this parameter.

  ip_whitelist: "0.0.0.0/0"
  # Blocks from which Attack Range machines can be reached.
  # This allow comma-separated blocks
  # ip_whitelist = 0.0.0.0/0,35.153.82.195/32

  crowdstrike_falcon: "0"
  # Enable/Disable CrowdStrike Falcon by setting this to 1 or 0.

  crowdstrike_agent_name: "WindowsSensor.exe"
  crowdstrike_customer_ID: ""
  crowdstrike_logs_region: ""
  crowdstrike_logs_access_key_id: ""
  crowdstrike_logs_secret_access_key: ""
  crowdstrike_logs_sqs_url: ""
  # All these fields are needed to automatically deploy a CrowdStrike Agent and ingest CrowdStrike Falcon logs into the Splunk Server.
  # See the chapter CrowdStrike Falcon in the docs page Attack Range Features.

  carbon_black_cloud: "0"
  # Enable/Disable VMWare Carbon Black Cloud by setting this to 1 or 0.

  carbon_black_cloud_agent_name: "installer_vista_win7_win8-64-3.8.0.627.msi"
  carbon_black_cloud_company_code: ""
  carbon_black_cloud_s3_bucket: ""
  # All these fields are needed to automatically deploy a Carbon Black Agent and ingest Carbon Black logs into the Splunk Server.
  # See the chapter Carbon Black in the docs page Attack Range Features.

  install_contentctl: "0"
  # Install splunk/contentctl on linux servers

aws:
  region: "us-west-2"
  # Region used in AWS. This should be the same as the region configured in AWS CLI.

  private_key_path: "~/.ssh/id_rsa"
  # Path to your private key. This needs to match the public key uploaded to AWS.

  cloudtrail: "0"
  # Enable/Disable collection of CloudTrail logs by setting this to 1 or 0.

  cloudtrail_sqs_queue: "https://sqs.us-west-2.amazonaws.com/111111111111/cloudtrail-cloud-attack-range"
  # Cloudtrail SQS queue. See the chapter AWS CloudTrail in the docs page Attack Range Cloud.

  use_elastic_ips: "1"
  # Enable/disable usage of Elastic IPs by setting this to 1 or 0.

  use_remote_state: "0"
  # Store the state file in s3 and dynamoDB instead of local

  tf_remote_state_s3_bucket: "test"
  # Specify the already created S3 bucket in the same region

  tf_remote_state_dynamo_db_table: "test"
# Specify the already created DynamoDB table in the same region

azure:
  location: "West Europe"
  # Region used in Azure.

  subscription_id: "xxx"
  # Azure subscription ID.

  private_key_path: "~/.ssh/id_rsa"
  # Path to your private key.

  public_key_path: "~/.ssh/id_rsa.pub"
  # Path to your public key.

  azure_logging: "0"
  # Enable/Disable Azure logs and onboard them into the Splunk Server by setting this to 1 or 0.

  client_id: "xxx"
  client_secret: "xxx"
  tenant_id: "xxx"
  event_hub_name: "xxx"
  event_hub_host_name: "xxx"
# All these fields are needed to configure the Azure logs. See the chapter Azure Logs in the docs page Attack Range Cloud.

local:
  provider: "Virtual Box"
# Attack Range Local used Virtualbox and Vagrant to build the Attack Range.

splunk_server:

  install_es: "0"
  # Enable/Disable Enterprise Security by setting this to 1 or 0.

  splunk_es_app: "splunk-enterprise-security_731.spl"
  # File name of the Enterprise Security spl file. Needs to be located in the apps folder.

  s3_bucket_url: "https://attack-range-appbinaries.s3-us-west-2.amazonaws.com"
  # S3 bucket containing the Splunk Apps which will be installed in Attack Range.

  splunk_url: "https://download.splunk.com/products/splunk/releases/9.3.0/linux/splunk-9.3.0-51ccf43db5bd-Linux-x86_64.tgz"
  # Url to download Splunk Enterprise.

  splunk_uf_url: "https://download.splunk.com/products/universalforwarder/releases/9.3.0/linux/splunkforwarder-9.3.0-51ccf43db5bd-linux-2.6-amd64.deb"
  # Url to download Splunk Universal Forwarder Linux.

  splunk_uf_win_url: "https://download.splunk.com/products/universalforwarder/releases/9.3.0/windows/splunkforwarder-9.3.0-51ccf43db5bd-x64-release.msi"
  # Url to download Splunk Universal Forwarder Windows.

  splunk_apps:
    - splunk-add-on-for-microsoft-windows_880.tgz
    - splunk-timeline-custom-visualization_162.tgz
    - status-indicator-custom-visualization_150.tgz
    - splunk-sankey-diagram-custom-visualization_160.tgz
    - punchcard-custom-visualization_150.tgz
    - splunk_attack_range_reporting-1.0.9.tar.gz
    - splunk-common-information-model-cim_532.tgz
    - DA-ESS-ContentUpdate-latest.tar.gz
    - python-for-scientific-computing-for-linux-64-bit_420.tgz
    - splunk-machine-learning-toolkit_541.tgz
    - splunk-security-essentials_380.tgz
    - splunk-add-on-for-sysmon_400.tgz
    - splunk-add-on-for-sysmon-for-linux_100.tgz
    - splunk-add-on-for-amazon-web-services-aws_760.tgz
    - splunk-add-on-for-microsoft-office-365_451.tgz
    - splunk-add-on-for-amazon-kinesis-firehose_131r7d1d093.tgz
    - splunk-add-on-for-unix-and-linux_910.tgz
    - ta-for-zeek_108.tgz
    - splunk-add-on-for-nginx_322.tgz
    - phantom-app-for-splunk_4035.tgz
    - TA-osquery.tar.gz
    - splunk-add-on-for-microsoft-cloud-services_530.tgz
    - splunk-add-on-for-crowdstrike-fdr_150.tgz
    - vmware-carbon-black-cloud_115.tgz
    - splunk-add-on-for-carbon-black_210.tgz
    - TA-aurora-0.2.0.tar.gz
    - snort-alert-for-splunk_111.tgz
  # List of Splunk Apps to install on the Splunk Server

  byo_splunk: "0"
  # Enable/Disable Bring your own Splunk by setting this to 1 or 0.

  byo_splunk_ip: ""
  # Specify Splunk IP address when you enable BYO Splunk.

  ingest_bots3_data: "0"
  # Ingest BOTS data to Attack Range.

  install_dltk: "0"
# Install Deep Learning Toolkit.

phantom_server:
  phantom_server: "0"
  # Enable/Disable Phantom Server

  phantom_app: "splunk_soar-unpriv-6.2.1.305-7c40b403-el7-x86_64.tgz"
  # name of the Splunk SOAR package located in apps folder

  phantom_byo: "0"
  # Enable/Disable Bring your own Phantom

  phantom_byo_ip: ""
  # Specify Phantom IP address when you enabled byo phantom

  phantom_byo_api_token: ""
# Phantom Api Token

windows_servers_default:
  hostname: ar-win
  # Define the hostname for the Windows Server.

  windows_image: "windows-server-2019"
  # Name of the image of the Windows Server. 

  create_domain: "0"
  # Create Domain will turn this Windows Server into a Domain Controller. Enable by setting this to 1.

  join_domain: "0"
  # Join a domain by setting this to 1 or 0.

  win_sysmon_config: "SwiftOnSecurity.xml"
  # Specify a Sysmon config located under configs/ .

  install_red_team_tools: "0"
  # Install different read team tools by setting this to 1 or 0.

  bad_blood: "0"
  # Install Bad Blood by setting this to 1 or 0.
  # More information in chapter Bad Blood under Attack Range Features.

  aurora_agent: "0"
  # Install Aurora Agent

  advanced_logging: "0"
  # Enable verbose windows security logs by setting this to 1.

linux_servers_default:
  hostname: ar-linux
  # Define the hostname for the Linux Server.

  sysmon_config: "SysMonLinux-CatchAll.xml"
# Specify a Sysmon config located under configs/ .

kali_server:
  kali_server: "0"
# Enable Kali Server by setting this to 1.

nginx_server:
  nginx_server: "0"
  # Enable Nginx Server by setting this to 1.

  hostname: "nginx"
  # Specify the image used for Nginx Server.

  proxy_server_ip: "10.0.1.12"
  # Specify what ip to proxy.

  proxy_server_port: "8000"
# Specify what port to proxy.

zeek_server:
  zeek_server: "0"
  # Enable Zeek Server by setting this to 1.

snort_server:
  snort_server: "0"
  # Enable Snort Server by setting this to 1.

simulation:
  atomic_red_team_repo: redcanaryco
  # Specify the repository owner for Atomic Red Team.

  atomic_red_team_branch: master
  # Specify the branch for Atomic Red Team.
````
