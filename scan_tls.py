import subprocess
import sys
import json
from datetime import datetime, timezone


def is_quantum_vulnerable(algorithm):
    # return True if algorithm is quantum vulnerable
    if algorithm in ['RSA', 'ECDSA', 'ECDH', 'DH', 'ECC']:
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
        if 'issuer=' in line:
            return line.split('issuer=')[1]
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

def scan_domain(domain):
    raw = get_tls_raw(domain)
    cert_details = get_cert_details(domain)  # add this
    version = get_tls_version(raw)
    algorithm = get_algorithm(raw)
    quantum_vulnerable = is_quantum_vulnerable(algorithm)
    keysize = get_key_size(raw)
    issuer = get_issuer(raw)
    expiry = get_expiry(cert_details)           # change raw to cert_details
    signature_algorithm = get_signature_algorithm(cert_details)  # change raw to cert_details
    days_until_expiry = get_days_until_expiry(expiry)
    risk_level = get_risk_level(algorithm, days_until_expiry)
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
        'risk_level': risk_level
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

if __name__ == '__main__':
    target = sys.argv[1]
    if target.endswith('.csv'):
        results = scan_multiple(target)
        print(json.dumps(results, indent=2))
    else:
        result = scan_domain(target)
        print(json.dumps(result, indent=2))