import subprocess
import sys
import json
from datetime import datetime, timezone
import requests
import uuid

def is_quantum_vulnerable(algorithm):
    # return True if algorithm is quantum vulnerable
    if algorithm in ['RSA', 'ECDSA', 'ECDH', 'DH', 'ECC', 'X25519', 'Ed25519']:
        return True
    else:
        return False

def get_tls_raw(domain):
    # A function that takes a domain like "example.com"
# and runs this shell command:
#   openssl s_client -connect example.com:443 </dev/null 2>&1
# and returns the output as a string
#
# Hint: use subprocess.run()
# Parameters you need: capture_output=True, text=True
    result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain, '-showcerts'], capture_output=True, text=True, input='')
    return result.stdout

def get_tls_version(raw_output):
    # loop through each line
    # if the line contains 'Protocol'
    # return the version (the part after the colon, stripped of whitespace)
    # if nothing found, return 'Unknown

    for line in raw_output.split('\n'):
        if 'Protocol' in line:
            return line.split(':')[1].strip()
    return 'Unknown'

def get_cert_details(domain):
    # step 1: get raw connection output
    conn = subprocess.run(
        ['openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain],
        capture_output=True, text=True, input=''
    )
    # step 2: feed it to x509 to extract dates and signature algorithm
    cert = subprocess.run(
        ['openssl', 'x509', '-noout', '-enddate', '-text'],
        input=conn.stdout,
        capture_output=True, text=True
    )
    return cert.stdout

def get_algorithm(raw_output):
    for line in raw_output.split('\n'):
        if 'Server Temp Key' in line:
            # "Server Temp Key: ECDH, X25519, 253 bits"
            parts = line.split(':')[1].strip().split(',')
            return parts[0].strip()
        if 'Server public key' in line and 'bit' in line:
            parts = line.split()
            # try to get word after 'bit'
            idx = parts.index('bit')
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return 'Unknown'

def get_key_size(raw_output):
    # look for the line containing 'Server public key'
    # that line looks like: "Server public key is 256 bit"
    # return the number (256) as an integer
    # return None if not found
    for line in raw_output.split('\n'):
        if 'Server public key' in line:
            return int(line.split()[-2])
    return None

def get_issuer(raw_output):
    # look for the line containing 'issuer='
    # that line looks like: "issuer=/C=US/O=Google Trust Services/CN=WE2"
    # return everything after 'issuer='
    # return 'Unknown' if not found
    for line in raw_output.split('\n'):
        if 'Issuer:' in line and 'Public Key' not in line:
            return line.split('Issuer:')[1].strip()
    return 'Unknown'

def get_expiry(raw_output):
    # look for a line containing 'notAfter' OR 'NotAfter'
    # that line looks like: "notAfter=Jul 30 15:51:35 2026 GMT"
    # return everything after the '='
    # return 'Unknown' if not found
    for line in raw_output.split('\n'):
        if 'notAfter' in line or 'NotAfter' in line:
            return line.split('=')[1]
    return 'Unknown'

def get_signature_algorithm(raw_output):
    # look for line containing 'Signature Algorithm'
    # line looks like: "Signature Algorithm: ecdsa-with-SHA256"
    # return everything after the ': '
    # return 'Unknown' if not found
    for line in raw_output.split('\n'):
        if 'Signature Algorithm' in line:
            return line.split(': ')[1]
    return 'Unknown'

def get_days_until_expiry(expiry_string):
    if expiry_string == 'Unknown':
        return None
    try:
        expiry_date = datetime.strptime(expiry_string.strip(), '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        delta = expiry_date - datetime.now(timezone.utc)
        return delta.days
    except Exception as e:
        return None

def get_risk_level(algorithm, days_until_expiry):
    if not is_quantum_vulnerable(algorithm):
        return 'Low'
    if days_until_expiry is not None and days_until_expiry < 60:
        return 'Critical'
    return 'High'

def get_pqc_status(algorithm):
    # if algorithm contains 'MLKEM' or 'Kyber' return 'hybrid_pqc'
    # if algorithm is in the quantum vulnerable list return 'vulnerable'
    # otherwise return 'unknown'
    if 'MLKEM' in algorithm or 'Kyber' in algorithm:
        return 'hybrid_pqc'
    if is_quantum_vulnerable(algorithm):
        return 'vulnerable'
    return 'unknown'

def get_subject(raw_output):
     # look for line containing 'subject='
    # line looks like: "subject=/CN=*.google.com"
    # return everything after 'subject='
    # return 'Unknown' if not found
    for line in raw_output.split('\n'):
        if 'Subject:' in line and 'Public Key' not in line:
            return line.split('Subject:')[1].strip()
    return 'Unknown'

def save_results(results):
    # generate a filename using datetime.now().strftime('%Y%m%d_%H%M%S')
    # filename should look like: scan_results_20260609_143022.json
    # save results as formatted JSON to that file
    # print a message saying where it saved
    filename = f'scan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'Results saved to {filename}')

def get_certs_from_ct_logs(domain):
    try:
        url = f'https://crt.sh/?q=%.{domain}&output=json&exclude=expired'
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
        certs = sorted(response.json(), key=lambda x: x['not_after'], reverse=True)[:5]
        results = []
        for cert in certs:
            results.append({
                'issuer': cert['issuer_name'],
                'common_name': cert['common_name'],
                'not_before': cert['not_before'],
                'not_after': cert['not_after']
            })
        return results
    except Exception as e:
        return []

def scan_domain(domain):
    raw = get_tls_raw(domain)
    cert_details = get_cert_details(domain)  # add this
    version = get_tls_version(raw)
    algorithm = get_algorithm(raw)
    quantum_vulnerable = is_quantum_vulnerable(algorithm)
    keysize = get_key_size(raw)
    issuer = get_issuer(cert_details)
    expiry = get_expiry(cert_details)
    signature_algorithm = get_signature_algorithm(cert_details)
    days_until_expiry = get_days_until_expiry(expiry)
    risk_level = get_risk_level(algorithm, days_until_expiry)
    pqc_status = get_pqc_status(algorithm)
    subject = get_subject(cert_details)
    ct_logs = get_certs_from_ct_logs(domain)
    return {
       'domain': domain,
        'tls_version': version,
        'algorithm': algorithm,
        'quantum_vulnerable': quantum_vulnerable,
        'keysize': keysize,
        'issuer': issuer,
        'expiry': expiry,
        'signature_algorithm': signature_algorithm, 
        'days_until_expiry': days_until_expiry, 
        'risk_level': risk_level,
        'pqc_status': pqc_status,
        'subject': subject,
        'ct_logs': ct_logs
        }

def scan_multiple(csv_file):
    # open the file
    # loop each line, strip whitespace
    # skip empty lines
    # call scan_domain() on each
    # return list of results
    results = []
    with open(csv_file, 'r') as f:
        for line in f:
            domain = line.strip()
            if domain:
                result = scan_domain(domain)
                results.append(result)
    return results



def convert_to_cbom(scan_results):
    # scan_results is either a single dict or a list of dicts
    # if it's a single dict, wrap it in a list first
    # build the top level structure:
    #   bomFormat, specVersion, serialNumber, version, metadata, components
    # for each result in scan_results call a helper function
    #   build_component(result) that returns one component dict
    # return the full cbom dict
    if isinstance(scan_results, dict):
        scan_results = [scan_results]
    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': str(uuid.uuid4()),
        'version': 1,
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'component': {
                'type': 'application',
                'name': 'Cryptiq PQC Scanner'
            }
        },
        'components': []
    }

    for result in scan_results:
        bom['components'].append(build_component(result))
    return bom

def map_primitive(algorithm):
    mapping = {
        'ECDH': 'keyagree',
        'RSA': 'pke',
        'DH': 'keyagree',
        'ECDSA': 'signature',
        'ECC': 'pke',
        'X25519MLKEM768': 'kem',
        'Unknown': 'unknown'
    }
    return mapping.get(algorithm, 'unknown')

def build_component(result):
    return {
        'type': 'cryptographic-asset',
        'name': f"{result['domain']} TLS Certificate",
        'cryptoProperties': {
            'assetType': 'certificate',
            'algorithmProperties': {
                'primitive': map_primitive(result['algorithm']),
                'keySize': result['keysize'],
            },
            'nistQuantumSecurityLevel': 0 if result['quantum_vulnerable'] else 3,
            'certificateProperties': {
                'subjectName': result['subject'],
                'issuerName': result['issuer'],
                'notValidAfter': result['expiry'],
                'signatureAlgorithm': result['signature_algorithm']
            }
        },
        'properties': [
            {'name': 'quantum_vulnerable', 'value': str(result['quantum_vulnerable']).lower()},
            {'name': 'risk_level', 'value': result['risk_level']},
            {'name': 'pqc_status', 'value': result['pqc_status']},
            {'name': 'days_until_expiry', 'value': str(result['days_until_expiry'])},
            {'name': 'tls_version', 'value': result['tls_version']}
        ]
        
        }
    
    
def save_cbom(cbom, filename):
    with open(filename, 'w') as f:
        json.dump(cbom, f, indent=2)
    print(f'CBOM saved to {filename}')

if __name__ == '__main__':
    target = sys.argv[1]
    if target.endswith('.csv'):
        results = scan_multiple(target)
        print(json.dumps(results, indent=2))
        save_results(results)
        cbom_filename = f'cbom_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        save_cbom(convert_to_cbom(results), cbom_filename)
    else:
        result = scan_domain(target)
        print(json.dumps(result, indent=2))
        save_results(result)
        cbom_filename = f'cbom_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        save_cbom(convert_to_cbom(result), cbom_filename)