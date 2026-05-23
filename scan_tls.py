import subprocess
import sys
import json


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
    result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain], capture_output=True, text=True, input='')
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

def scan_domain(domain):
    # 1. call get_tls_raw(domain) to get the output
    # 2. call get_tls_version() on it
    # 3. get the algorithm — hint: look for a line containing 'Server public key'
    #    that line looks like: "Server public key is 2048 bit RSA"
    # 4. call is_quantum_vulnerable() on the algorithm
    # 5. return a dict with keys:
    #    domain, tls_version, algorithm, quantum_vulnerable
    raw = get_tls_raw(domain)
    version = get_tls_version(raw)
    algorithm = get_algorithm(raw)
    quantum_vulnerable = is_quantum_vulnerable(algorithm)
    return {'domain': domain, 'tls_version': version, 'algorithm': algorithm, 'quantum_vulnerable': quantum_vulnerable}


if __name__ == '__main__':
    domain = sys.argv[1]
    result = scan_domain(domain)
    print(json.dumps(result, indent=2))