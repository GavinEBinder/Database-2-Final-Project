import requests
import time

cpe_names = [
    "cpe:2.3:a:google:chrome:1:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:25:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:50:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:75:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:100:*:*:*:*:*:*:*"
]

# NVD API base URL
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
results_per_page = 10  # Maximum allowed value for efficient pagination

# Open file to store SQL statements
with open("CVE_Database.sql", "w") as sql_file:
    for cpe_name in cpe_names:
        print(f"Fetching CVEs for {cpe_name}...")
        start_index = 0  # Start from the beginning
        total_results = None

        while total_results is None or start_index < total_results:
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()

                data = response.json()
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                print(f"Fetched {len(vulnerabilities)} vulnerabilities (startIndex: {start_index})")

                # Write each CVE to the SQL file
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cve", {}).get("id")
                    cvss_score = None
                    metrics = data.get('metrics', {})
                    cvss_v2_metrics = metrics.get('cvssMetricV2', [])

                    if isinstance(cvss_v2_metrics, list) and cvss_v2_metrics:
                        cvss_score = cvss_v2_metrics[0].get('cvssData', {}).get('baseScore')
                    if cve_id:
                        cve_id = cve_id.replace("'", "''")  # Escape single quotes for SQL
                        cvss_score_value = cvss_score if cvss_score is not None else 'NULL'
                        sql_line = f"INSERT INTO cve_records (cve_id, cvss_score, cpe_name) VALUES ('{cve_id}', '{cvss_score_value}', '{cpe_name}');\n"
                        sql_file.write(sql_line)

                # Update the start index for the next page
                start_index += results_per_page
            

            except requests.RequestException as e:
                print(f"An error occurred for {cpe_name} (startIndex: {start_index}): {e}")
                break
            time.sleep(6)

print("Done fetching CVEs.")
