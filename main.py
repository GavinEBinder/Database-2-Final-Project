
import requests
import time
import json
"""
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

cpe_names = [
    "cpe:2.3:a:google:chrome:1:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:25:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:50:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:75:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:118:*:*:*:*:*:*:*"
]

start_index = 0

for cpe_name in cpe_names:

    params = {
        "resultsPerPage": 100,
        "cpeName": cpe_name,
        "startIndex": start_index
    }

    with open("CVE_Database.sql", "w") as sql_file:
        #try:
            response = requests.get(url, params=params)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for record in vulnerabilities:
                cve_data = record.get("cve", {})
                cve_id = cve_data.get('id')

                cvss_score = None
                metrics = cve_data.get('metrics', {})
                cvss_v2_metrics = metrics.get('cvssMetricV2', [])

                if isinstance(cvss_v2_metrics, list) and cvss_v2_metrics:
                    cvss_score = cvss_v2_metrics[0].get('cvssData', {}).get('baseScore')

                if cve_id:
                    cve_id = cve_id.replace("'", "''")  # Escape single quotes
                    cvss_score_value = cvss_score if cvss_score is not None else 'NULL'
                    sql_line = f"INSERT INTO cve_records (cve_id, cvss_score) VALUES ('{cve_id}', {cvss_score_value});\n"
                    sql_file.write(sql_line)
            start_index += 100

        #except requests.RequestException as e:
            #print(f"Failed to retrieve data: {e}")
        #except json.JSONDecodeError:
            #print("Error: Failed to decode JSON.")
"""

cpe_names = [
    "cpe:2.3:a:google:chrome:1:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:25:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:50:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:75:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:100:*:*:*:*:*:*:*"
]

# NVD API base URL
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
results_per_page = 200  # Maximum allowed value for efficient pagination
tracker = 0
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
                        sql_line = f"INSERT INTO cve_records (cve_id, cpe_name) VALUES ('{cve_id}', '{cvss_score_value}', '{cpe_name}');\n"
                        sql_file.write(sql_line)

                # Update the start index for the next page
                start_index += results_per_page
                if tracker == 4:
                    time.sleep(30)
                    tracker = 0
                else:
                    tracker += 1

            except requests.RequestException as e:
                print(f"An error occurred for {cpe_name} (startIndex: {start_index}): {e}")
                break

print("Done fetching CVEs.")