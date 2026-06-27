import requests
import boto3

def get_subdomains_from_ct(root_domain, retries=2):
    # Try crt.sh first
    for attempt in range(retries):
        try:
            url = f'https://crt.sh/?q=%.{root_domain}&output=json&exclude=expired'
            response = requests.get(url, timeout=10)
            if response.status_code == 200 and response.text.strip():
                certs = response.json()
                subdomains = [cert['common_name'] for cert in certs
                             if not cert['common_name'].startswith('*')]
                if subdomains:
                    return list(set(subdomains))
        except Exception:
            pass

    # Fallback: certspotter (more reliable)
    try:
        url = f'https://api.certspotter.com/v1/issuances?domain={root_domain}&include_subdomains=true&expand=dns_names'
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = []
            for cert in data:
                for name in cert.get('dns_names', []):
                    if not name.startswith('*') and root_domain in name:
                        subdomains.append(name)
            return list(set(subdomains))
    except Exception:
        pass

    return []


def get_domains_from_route53(region='us-east-1'):
    try:
        route53 = boto3.client('route53', region_name=region)
        zones = route53.list_hosted_zones()
        domains = []
        for zone in zones['HostedZones']:
            records = route53.list_resource_record_sets(HostedZoneId=zone['Id'])
            for record in records['ResourceRecordSets']:
                if record['Type'] in ['A', 'CNAME']:
                    domains.append(record['Name'].rstrip('.'))
        return list(set(domains))
    except Exception:
        return []
    



def get_ec2_hosts(region='us-east-1'):
    try:
        ec2 = boto3.client('ec2', region_name=region)
        instances = ec2.describe_instances()
        hosts = []
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                ip = instance.get('PublicIpAddress')
                if ip:
                    hosts.append(ip)
        return hosts
    except Exception:
        return []


def discover_assets(root_domain, region='us-east-1'):
    # 1. get subdomains from CT logs
    subdomains = get_subdomains_from_ct(root_domain)
    # 2. get domains from Route53
    domains = get_domains_from_route53(region)
    # 3. get EC2 hosts
    hosts = get_ec2_hosts(region)
    # 4. combine all into one dict and return
    #    return format:
    #    {
    #      'domains': [...],   # CT logs + Route53 combined, deduplicated
    #      'hosts': [...]      # EC2 IPs
    #    }
    return {
        'domains': list(set(subdomains + domains)),
        'hosts': hosts
    }


if __name__ == '__main__':
    print(discover_assets('example.com'))