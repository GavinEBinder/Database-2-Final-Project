USE cve_database;
DROP TABLE IF EXISTS browser_stats;
CREATE TABLE browser_stats (
    product VARCHAR(255),
    weighted_average DECIMAL(3,1),
    average_score DECIMAL(3,1),
    min_score DECIMAL(3,1),
    max_score DECIMAL(3,1),
    median_score DECIMAL(3,1),
    total_count INT,
    num_critical INT,
    num_high INT,
    num_medium INT,
    num_low INT
);

#Chrome
SET @rowindex := -1;
INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score, total_count, num_critical, num_high, num_medium, num_low)
SELECT
    'Chrome' AS product,
    SUM(cg.cvss_score * CASE
        WHEN cg.severity = 'LOW' THEN 0.2
        WHEN cg.severity = 'MEDIUM' THEN 0.8
        WHEN cg.severity = 'HIGH' THEN 1.5
        WHEN cg.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) / SUM(CASE
        WHEN cg.severity = 'LOW' THEN 0.2
        WHEN cg.severity = 'MEDIUM' THEN 0.8
        WHEN cg.severity = 'HIGH' THEN 1.5
        WHEN cg.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) AS weighted_average,
    AVG(cg.cvss_score) AS average_score,
    MIN(cg.cvss_score) AS min_score,
    MAX(cg.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score,
    COUNT(*) AS total_count,
    SUM(CASE WHEN cg.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS num_critical,
	SUM(CASE WHEN cg.severity = 'HIGH' THEN 1 ELSE 0 END) AS num_high,
	SUM(CASE WHEN cg.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS num_medium,
    SUM(CASE WHEN cg.severity = 'LOW' THEN 1 ELSE 0 END) AS num_low
FROM
    cve_records cg,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            cg.cvss_score
     FROM cve_records cg
     WHERE product LIKE "%chrome%" and vendor = "google"
     ORDER BY cg.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2)) AND product like "%chrome%" and vendor = "google";

#Edge
SET @rowindex := -1;
INSERT INTO browser_stats 
(product, weighted_average, average_score, min_score, max_score, median_score, total_count, num_critical, num_high, num_medium, num_low)
SELECT 'Edge' AS product,
    SUM(em.cvss_score * CASE
        WHEN em.severity = 'LOW' THEN 0.2
        WHEN em.severity = 'MEDIUM' THEN 0.8
        WHEN em.severity = 'HIGH' THEN 1.5
        WHEN em.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) / SUM(CASE
        WHEN em.severity = 'LOW' THEN 0.2
        WHEN em.severity = 'MEDIUM' THEN 0.8
        WHEN em.severity = 'HIGH' THEN 1.5
        WHEN em.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) AS weighted_average,
    AVG(em.cvss_score) AS average_score,
    MIN(em.cvss_score) AS min_score,
    MAX(em.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score,
    COUNT(*) AS total_count,
    SUM(CASE WHEN em.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS num_critical,
	SUM(CASE WHEN em.severity = 'HIGH' THEN 1 ELSE 0 END) AS num_high,
	SUM(CASE WHEN em.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS num_medium,
    SUM(CASE WHEN em.severity = 'LOW' THEN 1 ELSE 0 END) AS num_low
FROM cve_records em,
    (SELECT @rowindex := @rowindex + 1 AS rowindex, em.cvss_score
     FROM cve_records em
     WHERE product LIKE "%edge%" and vendor = "microsoft"
     ORDER BY em.cvss_score) AS d
WHERE d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2)) 
AND product like "%edge%" and vendor = "microsoft";

#FireFox

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score, total_count, num_critical, num_high, num_medium, num_low)
SELECT
    'Firefox' AS product,
    SUM(fm.cvss_score * CASE
        WHEN fm.severity = 'LOW' THEN 0.2
        WHEN fm.severity = 'MEDIUM' THEN 0.8
        WHEN fm.severity = 'HIGH' THEN 1.5
        WHEN fm.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) / SUM(CASE
        WHEN fm.severity = 'LOW' THEN 0.2
        WHEN fm.severity = 'MEDIUM' THEN 0.8
        WHEN fm.severity = 'HIGH' THEN 1.5
        WHEN fm.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) AS weighted_average,
    AVG(fm.cvss_score) AS average_score,
    MIN(fm.cvss_score) AS min_score,
    MAX(fm.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score,
    COUNT(*) AS total_count,
    SUM(CASE WHEN fm.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS num_critical,
	SUM(CASE WHEN fm.severity = 'HIGH' THEN 1 ELSE 0 END) AS num_high,
	SUM(CASE WHEN fm.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS num_medium,
    SUM(CASE WHEN fm.severity = 'LOW' THEN 1 ELSE 0 END) AS num_low
FROM
    cve_records fm,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            fm.cvss_score
     FROM cve_records fm
     WHERE product LIKE "%firefox%" and vendor = "mozilla"
     ORDER BY fm.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2)) AND product like "%firefox%" and vendor = "mozilla";

#Safari

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score, total_count, num_critical, num_high, num_medium, num_low)
SELECT
    'Safari' AS product,
    SUM(sa.cvss_score * CASE
        WHEN sa.severity = 'LOW' THEN 0.2
        WHEN sa.severity = 'MEDIUM' THEN 0.8
        WHEN sa.severity = 'HIGH' THEN 1.5
        WHEN sa.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) / SUM(CASE
        WHEN sa.severity = 'LOW' THEN 0.2
        WHEN sa.severity = 'MEDIUM' THEN 0.8
        WHEN sa.severity = 'HIGH' THEN 1.5
        WHEN sa.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) AS weighted_average,
    AVG(sa.cvss_score) AS average_score,
    MIN(sa.cvss_score) AS min_score,
    MAX(sa.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score,
    COUNT(*) AS total_count,
    SUM(CASE WHEN sa.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS num_critical,
	SUM(CASE WHEN sa.severity = 'HIGH' THEN 1 ELSE 0 END) AS num_high,
	SUM(CASE WHEN sa.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS num_medium,
    SUM(CASE WHEN sa.severity = 'LOW' THEN 1 ELSE 0 END) AS num_low
FROM
    cve_records sa,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            sa.cvss_score
     FROM cve_records sa
     WHERE product LIKE "%safari%" and vendor = "apple"
     ORDER BY sa.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2)) AND product like "%safari%" and vendor = "apple";

#Brave

SET @rowindex := -1;
INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score, total_count, num_critical, num_high, num_medium, num_low)
SELECT
    'Brave' AS product,
    SUM(bb.cvss_score * CASE
        WHEN bb.severity = 'LOW' THEN 0.2
        WHEN bb.severity = 'MEDIUM' THEN 0.8
        WHEN bb.severity = 'HIGH' THEN 1.5
        WHEN bb.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) / SUM(CASE
        WHEN bb.severity = 'LOW' THEN 0.2
        WHEN bb.severity = 'MEDIUM' THEN 0.8
        WHEN bb.severity = 'HIGH' THEN 1.5
        WHEN bb.severity = 'CRITICAL' THEN 3
        ELSE 0
    END) AS weighted_average,
    AVG(bb.cvss_score) AS average_score,
    MIN(bb.cvss_score) AS min_score,
    MAX(bb.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score,
    COUNT(*) AS total_count,
    SUM(CASE WHEN bb.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS num_critical,
	SUM(CASE WHEN bb.severity = 'HIGH' THEN 1 ELSE 0 END) AS num_high,
	SUM(CASE WHEN bb.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS num_medium,
    SUM(CASE WHEN bb.severity = 'LOW' THEN 1 ELSE 0 END) AS num_low
FROM
    cve_records bb,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            bb.cvss_score
     FROM cve_records bb
     WHERE product LIKE "%brave%" and vendor = "brave"
     ORDER BY bb.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2)) AND product like "%brave%" and vendor = "brave";
select * from browser_stats;
