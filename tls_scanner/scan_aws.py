import boto3
import json
from tls_scanner.scan_tls import is_quantum_vulnerable
import uuid
from datetime import datetime, timezone
from tls_scanner.scan_tls import map_primitive, is_quantum_vulnerable

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

def build_acm_component(cert):
    # return a cryptographic-asset component dict
    return {
        'type': 'cryptographic-asset',
        'name': f"{cert['domain_name']} TLS Certificate",
        'cryptoProperties': {
            'assetType': 'certificate',
            'algorithmProperties': {
                'primitive': map_primitive(cert['algorithm']),
                'keySize': cert['key_size'],
            },
            'nistQuantumSecurityLevel': 0 if cert['quantum_vulnerable'] else 3,
            'certificateProperties': {
                'subjectName': cert['domain_name'],
                'issuerName': cert['issuer'],
                'notValidAfter': cert['expiry'],
            }
        }
    }
    # use cert fields: domain_name, algorithm, key_size, issuer, expiry
    # assetType should be 'certificate'
    # use map_primitive() from scan_tls to map the algorithm

def build_kms_component(key):
    # return a cryptographic-asset component dict  
    return {
            'type': 'cryptographic-asset',
            'name': f"{key['key_id']} KMS Key",
            'cryptoProperties': {
                'assetType': 'relatedCryptoMaterial',
                'algorithmProperties': {
                    'primitive': map_primitive(key['algorithm']),
                },
                'nistQuantumSecurityLevel': 0 if key['quantum_vulnerable'] else 3,
            },
            'properties': [
                {'name': 'description', 'value': key['description']},
                {'name': 'status', 'value': key['status']},
                {'name': 'quantum_vulnerable', 'value': str(key['quantum_vulnerable']).lower()}
            ]
        }

def convert_aws_to_cbom(cert_results, kms_results):
    # cert_results is the list from scan_acm_certificates()
    if isinstance(cert_results, dict):
        cert_results = [cert_results]
   
    # kms_results is the list from scan_kms_keys()
    if isinstance(kms_results, dict):
        kms_results = [kms_results]
    # build the top level CBOM structure same as convert_to_cbom()
    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': str(uuid.uuid4()),
        'version': 1,
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'component': {
                'type': 'application',
                'name': 'Cryptiq AWS Scanner'
            }
        },
        'components': []  # add this
}
    # for each cert in cert_results call build_acm_component()
    for cert in cert_results:
        bom['components'].append(build_acm_component(cert))
    # for each key in kms_results call build_kms_component()
    for key in kms_results:
        bom['components'].append(build_kms_component(key))
    # return the full cbom dict
    return bom
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