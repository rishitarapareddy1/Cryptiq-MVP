import boto3
import json
from tls_scanner.scan_tls import is_quantum_vulnerable

def get_acm_certificates(region='us-east-1'):
    # create a boto3 client for 'acm' in the given region
    acm = boto3.client('acm', region_name=region)
    # call list_certificates() on it
    response = acm.list_certificates()
    # the result has a key 'CertificateSummaryList'
    # return that list
    return response['CertificateSummaryList']

def get_certificate_details(cert_arn, region='us-east-1'):
    # create an acm client
    acm = boto3.client('acm', region_name=region)
    # call describe_certificate(CertificateArn=cert_arn)
    response = acm.describe_certificate(CertificateArn=cert_arn)
    # the result has a key 'Certificate'
    return response['Certificate']
    # return that dict

def scan_acm_certificates(region='us-east-1'):
    # call get_acm_certificates to get the list
    certs = get_acm_certificates(region)
    # for each cert in the list, get its ARN
    # the ARN is in cert['CertificateArn']
    results = []
    for cert in certs:
        arn = cert['CertificateArn']
        details = get_certificate_details(arn, region)
        domain_name = details.get('DomainName', 'Unknown')
        algorithm = details.get('KeyAlgorithm', 'Unknown')
        issuer = details.get('Issuer', 'Unknown')
        status = details.get('Status', 'Unknown')
        expiry = str(details.get('NotAfter', 'Unknown'))
        key_size = details.get('KeySize', None)
        quantum_vulnerable = is_quantum_vulnerable(algorithm)
    # call get_certificate_details for each one
    # build a result dict with these fields:
        results.append({
            'arn': arn,
            'domain_name': domain_name,
            'algorithm': algorithm,
            'key_size': key_size,
            'status': status,
            'expiry': expiry,
            'issuer': issuer,
            'quantum_vulnerable': quantum_vulnerable
        })
    #   arn, domain_name, algorithm, key_size, 
    #   status, expiry, issuer, quantum_vulnerable
    # return list of results
    return results

def get_kms_keys(region='us-east-1'):
    # create a boto3 client for 'kms' in the given region
    kms = boto3.client('kms', region_name=region)
    # call list_keys()
    response = kms.list_keys()
    # result has a key 'Keys'
    # return that list
    return response['Keys']

def get_kms_key_details(key_id, region='us-east-1'):
    # create a kms client
    kms = boto3.client('kms', region_name=region)
    # call describe_key(KeyId=key_id)
    response = kms.describe_key(KeyId=key_id)
    # result has a key 'KeyMetadata'
    # return that dict
    return response['KeyMetadata']

def scan_kms_keys(region='us-east-1'):
    # call get_kms_keys to get the list
    keys = get_kms_keys(region)
    # each key has a 'KeyId' field
    results = []
    for key in keys:
        key_id = key['KeyId']
        details = get_kms_key_details(key_id, region)
        algorithm = details.get('KeyAlgorithm', 'Unknown')
        status = details.get('KeyState', 'Unknown')
        description = details.get('Description', 'Unknown')
        quantum_vulnerable = is_quantum_vulnerable(algorithm)
    # call get_kms_key_details for each one
    # build a result dict with these fields:
    #   key_id, algorithm, status, description, quantum_vulnerable
        results.append({
            'key_id': key_id,
            'algorithm': algorithm,
            'status': status,
            'description': description,
            'quantum_vulnerable': quantum_vulnerable
        })
    # hint: KeyMetadata has fields:
    #   KeyId, KeyAlgorithm, KeyState, Description
    # return list of results
    return results
#if __name__ == '__main__':
    # call scan_acm_certificates
    #results = scan_acm_certificates()
    # print results as formatted JSON
   # print(json.dumps(results, indent=4))
    # call scan_kms_keys
   # results = scan_kms_keys()
    # print results as formatted JSON
   # print(json.dumps(results, indent=4))
if __name__ == '__main__':
    print("Scanning ACM certificates...")
    cert_results = scan_acm_certificates()
    print(f"Found {len(cert_results)} certificates")
    print(json.dumps(cert_results, indent=2))
    
    print("\nScanning KMS keys...")
    kms_results = scan_kms_keys()
    print(f"Found {len(kms_results)} KMS keys")
    print(json.dumps(kms_results, indent=2))