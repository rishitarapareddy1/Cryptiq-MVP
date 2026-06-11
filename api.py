from scan_tls import scan_domain, convert_to_cbom
# 1. imports
from fastapi import FastAPI
from pydantic import BaseModel
# also import scan_domain and convert_to_cbom from your scanner file

# 2. create the app
app = FastAPI()

# 3. define the request model
# this tells FastAPI what the request body looks like
class ScanRequest(BaseModel):
    domain: str
   
# 4. create the endpoint
# @app.post("/scan") means: when someone sends a POST request to /scan, run this function
@app.post("/scan")
def scan(request: ScanRequest):
    # call scan_domain with request.domain
    # call convert_to_cbom with the result
    # return both
    result = scan_domain(request.domain)
    cbom = convert_to_cbom(result)
    return {"result": result, "cbom": cbom}

# endpoint 1 — health check
# GET /health
# returns {"status": "ok"}
# this is standard for any API — lets you verify it's running

@app.get("/health")
def health():
    # your code
    return {"status": "ok"}
# endpoint 2 — bulk scan
# POST /scan/bulk
# request body: { "domains": ["google.com", "github.com", "stripe.com"] }
# returns list of scan results + one combined CBOM

class BulkScanRequest(BaseModel):
    domains: list[str]

@app.post("/scan/bulk")
def bulk_scan(request: BulkScanRequest):
    # loop through request.domains
    # call scan_domain on each
    # convert all results to one CBOM
    # return results and cbom
    results = []
    for domain in request.domains:
        result = scan_domain(domain)
        results.append(result)
    cbom = convert_to_cbom(results)
    return {"results": results, "cbom": cbom}