DROP TABLE IF EXISTS browser_stats;
CREATE TABLE browser_stats (
    product VARCHAR(50),
    weighted_average FLOAT,
    average_score FLOAT,
    min_score FLOAT,
    max_score FLOAT,
    median_score FLOAT
);

#Chrome

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score)
SELECT
    'Chrome' AS product,
    SUM(cg.cvss_score * CASE
        WHEN cg.severity = 'LOW' THEN 1
        WHEN cg.severity = 'MEDIUM' THEN 2
        WHEN cg.severity = 'HIGH' THEN 3
        WHEN cg.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) / SUM(CASE
        WHEN cg.severity = 'LOW' THEN 1
        WHEN cg.severity = 'MEDIUM' THEN 2
        WHEN cg.severity = 'HIGH' THEN 3
        WHEN cg.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) AS weighted_average,
    AVG(cg.cvss_score) AS average_score,
    MIN(cg.cvss_score) AS min_score,
    MAX(cg.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score
FROM
    chrome_google cg,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            cg.cvss_score
     FROM chrome_google cg
     ORDER BY cg.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2));

#Edge

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score)
SELECT
    'Edge' AS product,
    SUM(em.cvss_score * CASE
        WHEN em.severity = 'LOW' THEN 1
        WHEN em.severity = 'MEDIUM' THEN 2
        WHEN em.severity = 'HIGH' THEN 3
        WHEN em.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) / SUM(CASE
        WHEN em.severity = 'LOW' THEN 1
        WHEN em.severity = 'MEDIUM' THEN 2
        WHEN em.severity = 'HIGH' THEN 3
        WHEN em.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) AS weighted_average,
    AVG(em.cvss_score) AS average_score,
    MIN(em.cvss_score) AS min_score,
    MAX(em.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score
FROM
    edge_microsoft em,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            em.cvss_score
     FROM edge_microsoft em
     ORDER BY em.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2));
    
#FireFox

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score)
SELECT
    'Firefox' AS product,
    SUM(fm.cvss_score * CASE
        WHEN fm.severity = 'LOW' THEN 1
        WHEN fm.severity = 'MEDIUM' THEN 2
        WHEN fm.severity = 'HIGH' THEN 3
        WHEN fm.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) / SUM(CASE
        WHEN fm.severity = 'LOW' THEN 1
        WHEN fm.severity = 'MEDIUM' THEN 2
        WHEN fm.severity = 'HIGH' THEN 3
        WHEN fm.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) AS weighted_average,
    AVG(fm.cvss_score) AS average_score,
    MIN(fm.cvss_score) AS min_score,
    MAX(fm.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score
FROM
    firefox_mozilla fm,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            fm.cvss_score
     FROM firefox_mozilla fm
     ORDER BY fm.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2));

#Safari

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score)
SELECT
    'Safari' AS product,
    SUM(sa.cvss_score * CASE
        WHEN sa.severity = 'LOW' THEN 1
        WHEN sa.severity = 'MEDIUM' THEN 2
        WHEN sa.severity = 'HIGH' THEN 3
        WHEN sa.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) / SUM(CASE
        WHEN sa.severity = 'LOW' THEN 1
        WHEN sa.severity = 'MEDIUM' THEN 2
        WHEN sa.severity = 'HIGH' THEN 3
        WHEN sa.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) AS weighted_average,
    AVG(sa.cvss_score) AS average_score,
    MIN(sa.cvss_score) AS min_score,
    MAX(sa.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score
FROM
    safari_apple sa,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            sa.cvss_score
     FROM safari_apple sa
     ORDER BY sa.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2));

#Brave

SET @rowindex := -1;

INSERT INTO browser_stats (product, weighted_average, average_score, min_score, max_score, median_score)
SELECT
    'Brave' AS product,
    SUM(bb.cvss_score * CASE
        WHEN bb.severity = 'LOW' THEN 1
        WHEN bb.severity = 'MEDIUM' THEN 2
        WHEN bb.severity = 'HIGH' THEN 3
        WHEN bb.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) / SUM(CASE
        WHEN bb.severity = 'LOW' THEN 1
        WHEN bb.severity = 'MEDIUM' THEN 2
        WHEN bb.severity = 'HIGH' THEN 3
        WHEN bb.severity = 'CRITICAL' THEN 4
        ELSE 0
    END) AS weighted_average,
    AVG(bb.cvss_score) AS average_score,
    MIN(bb.cvss_score) AS min_score,
    MAX(bb.cvss_score) AS max_score,
    AVG(d.cvss_score) AS median_score
FROM
    brave_brave bb,
    (SELECT @rowindex := @rowindex + 1 AS rowindex,
            bb.cvss_score
     FROM brave_brave bb
     ORDER BY bb.cvss_score) AS d
WHERE
    d.rowindex IN (FLOOR(@rowindex / 2), CEIL(@rowindex / 2));
