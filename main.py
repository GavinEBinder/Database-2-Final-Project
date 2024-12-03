import json
import os
import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="cve_database"
)
cursor = conn.cursor()

sql_line = "DROP SCHEMA IF EXISTS cve_database"
print("executing create schema")
cursor.execute(sql_line)

sql_line = "CREATE SCHEMA IF NOT EXISTS cve_database"
print("executing create schema")
cursor.execute(sql_line)

sql_line = "USE cve_database"
print("executing create schema")
cursor.execute(sql_line)

sql_line = "CREATE TABLE IF NOT EXISTS cve_records (cve_id varchar(255), product varchar(1000), vendor varchar(255), cvss_score decimal(3,1), severity varchar(255))"
print("executing create table")
cursor.execute(sql_line)

conn.commit()

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
            if len(product) >= 1000:
                continue
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
                cveID = data['cveMetadata']['cveId']
            except(KeyError, IndexError):
                cveID = "n/a"
            try:
                cvssScore_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseScore']
            except(KeyError, IndexError):
                cvssScore_2 = "n/a"
            try:
                severity_2 = data['containers']['cna']['metrics'][0]['cvssV2']['baseSeverity']
            except(KeyError, IndexError):
                severity_2 = "n/a"
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
        cvssScore = "n/a"
        severity = "n/a"
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
        if cvssScore != "n/a" or severity != "n/a":
            sql_line = ("INSERT INTO cve_records (cve_id, product, vendor, cvss_score, severity)"
                        "VALUES (%s, %s, %s, %s, %s)"
                        )
            print("executing insert")
            cursor.execute(sql_line, (cveID, product, vendor, cvssScore, severity))
            conn.commit()
        print(cveID)

cursor.close()
conn.close()
