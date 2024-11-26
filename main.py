import json
import os

def contains_word(word, text):
    return word.lower() in text.lower()

for root, dirs, files in os.walk('cves'):
    json_files = [f for f in files if f.endswith('.json')]
    for file in json_files:
        file_path = os.path.join(root, file)
        with open(file_path, encoding='utf-8') as json_file:
            data = json.load(json_file)
            try:
                product = data['containers']['cna']['affected'][0]['product']
                vendor = data['containers']['cna']['affected'][0]['vendor']
                version = data['containers']['cna']['affected'][0]['versions'][0]['version']
            except(KeyError, IndexError):
                product = vendor = version = "N/A"

            try:
                cvssScore_3_1 = data['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore']
                severity_3_1 = data['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity']
            except(KeyError, IndexError):
                cvssScore_3_1 = "n/a"
                severity_3_1 = "n/a"

            if cvssScore_3_1 == "n/a":
                try:
                    cvssScore_3_1 = data['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseScore']
                    severity_3_1 = data['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseSeverity']
                except(KeyError, IndexError):
                    cvssScore_3_1 = "n/a"
                    severity_3_1 = "n/a"

            try:
                cvssScore_3 = data['containers']['cna']['metrics'][0]['cvssV3']['baseScore']
                severity_3 = data['containers']['cna']['metrics'][0]['cvssV3']['baseSeverity']
            except(KeyError, IndexError):
                cvssScore_3 = "n/a"
                severity_3 = "n/a"

            try:
                description = data['containers']['cna']['descriptions'][0]['value']
            except(KeyError, IndexError):
                description = "n/a"


            try:
                cveID = data['cveMetadata']['cveId']
                assignerShortName = data['cveMetadata']['assignerShortName']
            except(KeyError, IndexError):
                cveID = "n/a"
                assignerShortName = "n/a"

            try:
                cvssScore_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseScore']
                severity_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseSeverity']
            except(KeyError, IndexError):
                cvssScore_2 = "n/a"
                severity_2 = "n/a"

            if product != "chrome" and product != "safari" and product != "edge" and product != "firefox" and product != "brave":
                product = "n/a"

            if vendor != "google" and vendor != "apple" and vendor != "microsoft" and vendor != "mozilla" and vendor != "brave":
                vendor = "n/a"

            if assignerShortName != "chrome" and assignerShortName != "safari" and assignerShortName != "edge" and assignerShortName != "firefox" and assignerShortName != "brave" and assignerShortName != "google" and assignerShortName != "apple" and assignerShortName != "microsoft" and assignerShortName != "mozilla" and assignerShortName != "brave":
                assignerShortName = "n/a"

            if contains_word("firefox", description):
                vendor = "mozilla"
                product = "firefox"
            elif contains_word("chrome", description) and contains_word("google", description):
                vendor = "google"
                product = "chrome"
            elif contains_word("brave", description):
                vendor = "brave"
                product = "brave"
            elif contains_word("safari", description):
                vendor = "apple"
                product = "safari"
            elif contains_word("edge", description) and contains_word("microsoft", description):
                vendor = "microsoft"
                product = "edge"
            else:
                vendor = "n/a"
                product = "n/a"
                description = "n/a"

            try:
                prod = data['containers']['cna']['affected'][0]['product']
            except(KeyError, IndexError):
                prod = "n/a"
            #print(prod)

            try:
                assigner = data['cveMetadata']['assignerShortName']
            except(KeyError, IndexError):
                assigner = "n/a"

            try:
                desc = data['containers']['cna']['descriptions'][0]['value']
            except(KeyError, IndexError):
                desc = "n/a"

        #print("Prod: ", prod, "; cveID: ", cveID, "; Product: ", product, "; vendor: ", vendor, "; assignerShortName: ", assignerShortName)
        #print("cveID: ", cveID, "; Product: ", product, "; vendor: ", vendor, "; desc: ", desc)
        #print("")
        if contains_word("safari", vendor) or contains_word("safari", assignerShortName) or contains_word("safari", description):
            print("cveID: ", cveID, "; Product: ", product, "; vendor: ", vendor, "; desc: ", desc)
        '''if cvssScore_3_1 == "n/a" and severity_3_1 == "n/a" and cvssScore_3 == "n/a" and severity_3 == "n/a" and cvssScore_2 == "n/a" and severity_2 == "n/a":
            print("Removed: ", cveID)
            os.remove(file_path)
        if not contains_word("chrome", desc) and not contains_word("safari", desc) and not contains_word("edge", desc) and not contains_word("firefox", desc) and not contains_word("google", desc) and not contains_word("apple", desc) and not contains_word("microsoft", desc) and not contains_word("mozilla", desc) and not contains_word("brave", desc):
        #if assigner != "chrome" and assigner != "safari" and assigner != "edge" and assigner != "firefox" and assigner != "google" and assigner != "apple" and assigner != "microsoft" and assigner != "mozilla" and assigner != "brave" and assigner != "n/a":
            print("Removed: ", cveID)
            os.remove(file_path)
        elif product == "n/a" and vendor == "n/a" and description == "n/a" and assignerShortName == "n/a":
            print("Removed: ", cveID)
            os.remove(file_path)'''

'''
with open("CVE_Database.sql", "w") as sql_file:
    for root, dirs, files in os.walk('cves'):
        json_files = [f for f in files if f.endswith('.json')]
        for file in json_files:
            file_path = os.path.join(root, file)
            with open(file_path, encoding='utf-8') as json_file:
                data = json.load(json_file)
                try:
                    product = data['containers']['cna']['affected'][0]['product']
                    vendor = data['containers']['cna']['affected'][0]['vendor']
                    version = data['containers']['cna']['affected'][0]['versions'][0]['version']
                except(KeyError, IndexError):
                    product = vendor = version = "N/A"

                try:
                    cvssScore_3_1 = data['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore']
                    severity_3_1 = data['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity']
                except(KeyError, IndexError):
                    cvssScore_3_1 = "n/a"
                    severity_3_1 = "n/a"

                if cvssScore_3_1 == "n/a":
                    try:
                        cvssScore_3_1 = data['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseScore']
                        severity_3_1 = data['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseSeverity']
                    except(KeyError, IndexError):
                        cvssScore_3_1 = "n/a"
                        severity_3_1 = "n/a"

                try:
                    cvssScore_3 = data['containers']['cna']['metrics'][0]['cvssV3']['baseScore']
                    severity_3 = data['containers']['cna']['metrics'][0]['cvssV3']['baseSeverity']
                except(KeyError, IndexError):
                    cvssScore_3 = "n/a"
                    severity_3 = "n/a"

                try:
                    description = data['containers']['cna']['descriptions'][0]['value']
                except(KeyError, IndexError):
                    description = "n/a"


                try:
                    cveID = data['cveMetadata']['cveId']
                    assignerShortName = data['cveMetadata']['assignerShortName']
                except(KeyError, IndexError):
                    cveID = "n/a"
                    assignerShortName = "n/a"

                try:
                    cvssScore_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseScore']
                    severity_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseSeverity']
                except(KeyError, IndexError):
                    cvssScore_2 = "n/a"
                    severity_2 = "n/a"
                if contains_word("chrome", product) or contains_word("safari", product) or contains_word("edge", product) or contains_word("firefox", product) or contains_word("google", product) or contains_word("brave", product):
                    if cvssScore_3_1 != "n/a":
                        cvssScore = cvssScore_3_1
                    elif cvssScore_3 != "n/a":
                        cvssScore = cvssScore_3
                    elif cvssScore_2 != "n/a":
                        cvssScore = cvssScore_2
                    sql_line = f"INSERT INTO cve_records (cve_id, product, vendor, cvss_score) VALUES ('{cveID}', '{product}', '{vendor}', {cvssScore});\n"
                    print("Writing to SQL file:", sql_line)  # Debug: Print SQL line before writing
                    sql_file.write(sql_line)
'''
