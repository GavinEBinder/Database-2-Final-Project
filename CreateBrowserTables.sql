DROP TABLE IF EXISTS edge_microsoft;
CREATE TABLE edge_microsoft AS
SELECT * 
FROM cve_records 
WHERE product LIKE "%edge%" AND vendor = "Microsoft";

DROP TABLE IF EXISTS firefox_mozilla;
CREATE TABLE firefox_mozilla AS
SELECT * 
FROM cve_records 
WHERE product LIKE "%firefox%" AND vendor = "Mozilla";

DROP TABLE IF EXISTS chrome_google;
CREATE TABLE chrome_google AS
SELECT * 
FROM cve_records 
WHERE product LIKE "%chrome%" AND vendor = "Google";

DROP TABLE IF EXISTS safari_apple;
CREATE TABLE safari_apple AS
SELECT * 
FROM cve_records 
WHERE product LIKE "%safari%" AND vendor = "Apple";

DROP TABLE IF EXISTS brave_brave;
CREATE TABLE brave_brave AS
SELECT * 
FROM cve_records 
WHERE product LIKE "%brave%" AND vendor = "Brave";

