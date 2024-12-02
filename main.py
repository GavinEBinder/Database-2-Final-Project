import json
import os
import mysql.connector

def contains_word(word, text):
    return word.lower() in text.lower()

for root, dirs, files in os.walk('C:/Users/GBISB/PycharmProjects/pythonProject3/cves'):
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
            except(KeyError, IndexError):
                cvssScore_3_1 = "n/a"
            try:
                severity_3_1 = data['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity']
            except(KeyError, IndexError):
                severity_3_1 = "n/a"
            if cvssScore_3_1 == "n/a":
                try:
                    cvssScore_3_1 = data['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseScore']
                except(KeyError, IndexError):
                    cvssScore_3_1 = "n/a"
            if severity_3_1 == "n/a":
                try:
                    severity_3_1 = data['containers']['adp'][0]['metrics'][0]['cvssV3_1']['baseSeverity']
                except(KeyError, IndexError):
                    severity_3_1 = "n/a"
            try:
                cvssScore_3 = data['containers']['cna']['metrics'][0]['cvssV3']['baseScore']
            except(KeyError, IndexError):
                cvssScore_3 = "n/a"
            try:
                severity_3 = data['containers']['cna']['metrics'][0]['cvssV3']['baseSeverity']
            except(KeyError, IndexError):
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
            except(KeyError, IndexError):
                cvssScore_2 = "n/a"
            try:
                severity_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseSeverity']
            except(KeyError, IndexError):
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
            try:
                assigner = data['cveMetadata']['assignerShortName']
            except(KeyError, IndexError):
                assigner = "n/a"
            try:
                desc = data['containers']['cna']['descriptions'][0]['value']
            except(KeyError, IndexError):
                desc = "n/a"
        if cvssScore_3_1 == "n/a" and severity_3_1 == "n/a" and cvssScore_3 == "n/a" and severity_3 == "n/a" and cvssScore_2 == "n/a" and severity_2 == "n/a":
            os.remove(file_path)
        '''elif not contains_word("chrome", desc) and not contains_word("safari", desc) and not contains_word("edge", desc) and not contains_word("firefox", desc) and not contains_word("google", desc) and not contains_word("apple", desc) and not contains_word("microsoft", desc) and not contains_word("mozilla", desc) and not contains_word("brave", desc):
            print("Removed: ", cveID)
            os.remove(file_path)'''

with open("CVE_Database.sql", "w", encoding="utf-8") as sql_file:
    sql_line = "CREATE TABLE IF NOT EXISTS cve_records (cve_id INT PRIMARY KEY, product TEXT, vendor TEXT, cvss_score INT, severity TEXT);"
    sql_file.write(sql_line)
    for root, dirs, files in os.walk('C:/Users/GBISB/PycharmProjects/pythonProject3/cves'):
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
                if cvssScore_3_1 != "n/a":
                    cvssScore = cvssScore_3_1
                    severity = severity_3_1
                elif cvssScore_3 != "n/a":
                    cvssScore = cvssScore_3
                    severity = severity_3
                elif cvssScore_2 != "n/a":
                    cvssScore = cvssScore_2
                    severity = severity_2
                elif cvssScore_3_1 == "n/a" and cvssScore_3 != "n/a" and cvssScore_2 != "n/a" and severity_3_1 != "n/a":
                    cvssScore = "n/a"
                    severity = severity_3_1
                elif cvssScore_3_1 == "n/a" and cvssScore_3 != "n/a" and cvssScore_2 != "n/a" and severity_3 != "n/a":
                    cvssScore = "n/a"
                    severity = severity_3
                elif cvssScore_3_1 == "n/a" and cvssScore_3 != "n/a" and cvssScore_2 != "n/a" and severity_2 != "n/a":
                    cvssScore = "n/a"
                    severity = severity_2
                sql_line = f"INSERT INTO cve_records (cve_id, product, vendor, cvss_score, severity) VALUES ('{cveID}', '{product}', '{vendor}', {cvssScore}, '{severity}');\n"
                sql_file.write(sql_line)

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="cve_database"
)

cursor = conn.cursor()
with open("CVE_Database.sql", "r", encoding="utf-8") as sql_file:
    sql_commands = sql_file.read()
    commands = sql_commands.split(";")
    for command in commands:
        command = command.strip()
        if command:
            cursor.execute(command)
            if command.lower().startswith("select"):
                results = cursor.fetchall()
                for row in results:
                    conn.commit()
                    if conn.is_connected():
                        cursor.close()
                        conn.close()
