# Supported ciphers statistics for the past month

SELECT  ciphersuites->>'cipher' as Ciphersuite,
        COUNT(DISTINCT(target)),
        (COUNT(DISTINCT(target)) * 100.0 / (
            SELECT COUNT(DISTINCT(target))
            FROM scans
            WHERE has_tls = True
            AND timestamp > NOW() - INTERVAL '1 month'
            )
        ) AS Percentage
FROM scans,
     jsonb_array_elements(conn_info->'ciphersuite') as ciphersuites
WHERE jsonb_typeof(conn_info) = 'object'
  AND jsonb_typeof(conn_info->'ciphersuite') = 'array'
  AND timestamp > NOW() - INTERVAL '1 month'
GROUP BY ciphersuites->>'cipher'
ORDER BY COUNT(DISTINCT(target)) DESC;

# Preferred ciphers statistics for the past month

SELECT  conn_info->'ciphersuite'->0->>'cipher' as "Preferred Ciphersuite",
        COUNT(DISTINCT(target)),
        (COUNT(DISTINCT(target)) * 100.0 / (
            SELECT COUNT(DISTINCT(target))
            FROM scans
            WHERE has_tls = True
            AND timestamp > NOW() - INTERVAL '1 month'
            )
        ) AS Percentage
FROM scans
WHERE jsonb_typeof(conn_info) = 'object'
  AND jsonb_typeof(conn_info->'ciphersuite') = 'array'
  AND timestamp > NOW() - INTERVAL '1 month'
GROUP BY conn_info->'ciphersuite'->0->>'cipher'
ORDER BY COUNT(DISTINCT(target)) DESC;


# Sites that prefer weak ciphers

SELECT  conn_info->'ciphersuite'->0->>'cipher' as Ciphersuite,
        COUNT(DISTINCT(target)),
        (COUNT(DISTINCT(target)) * 100.0 / (
            SELECT COUNT(DISTINCT(target))
            FROM scans
            WHERE has_tls = True
            AND timestamp > NOW() - INTERVAL '1 month'
            )
        ) AS Percentage
FROM scans
WHERE jsonb_typeof(conn_info) = 'object'
  AND jsonb_typeof(conn_info->'ciphersuite') = 'array'
  AND conn_info->'ciphersuite'->0->>'cipher' SIMILAR TO '(RC4|3DES|NULL|ADH|CAMELLIA|IDEA|GOST2001)-%'
  AND timestamp > NOW() - INTERVAL '1 month'
GROUP BY conn_info->'ciphersuite'->0->>'cipher'
ORDER BY COUNT(DISTINCT(target)) DESC;

# Server-Side Cipher ordering

SELECT  conn_info->'serverside' as "Server-Side Cipher Ordering",
        COUNT(DISTINCT(target)),
        (COUNT(DISTINCT(target)) * 100.0 / (
            SELECT COUNT(DISTINCT(target))
            FROM scans
            WHERE has_tls = True
            AND timestamp > NOW() - INTERVAL '1 month'
            )
        ) AS Percentage
FROM scans
WHERE has_tls = True
  AND timestamp > NOW() - INTERVAL '1 month'
  AND jsonb_typeof(conn_info->'serverside') = 'boolean'
GROUP BY conn_info->'serverside'
ORDER BY COUNT(DISTINCT(target)) DESC;

# Supported PFS

SELECT  ciphersuites->>'pfs' as pfs,
        COUNT(DISTINCT(target)),
        (COUNT(DISTINCT(target)) * 100.0 / (
            SELECT COUNT(DISTINCT(target))
            FROM scans
            WHERE has_tls = True
            AND timestamp > NOW() - INTERVAL '1 month'
            )
        ) AS Percentage
FROM scans,
     jsonb_array_elements(conn_info->'ciphersuite') as ciphersuites
WHERE jsonb_typeof(conn_info) = 'object'
  AND jsonb_typeof(conn_info->'ciphersuite') = 'array'
  AND timestamp > NOW() - INTERVAL '1 month'
  AND ciphersuites->>'pfs' != 'None'
GROUP BY ciphersuites->>'pfs'
ORDER BY COUNT(DISTINCT(target)) DESC;

# Supported Curves

SELECT  ciphersuites->>'pfs' as pfs,
        COUNT(DISTINCT(target)),
        (COUNT(DISTINCT(target)) * 100.0 / (
            SELECT COUNT(DISTINCT(target))
            FROM scans
            WHERE has_tls = True
            AND timestamp > NOW() - INTERVAL '1 month'
            )
        ) AS Percentage
FROM scans,
     jsonb_array_elements(conn_info->'ciphersuite') as ciphersuites
WHERE jsonb_typeof(conn_info) = 'object'
  AND jsonb_typeof(conn_info->'ciphersuite') = 'array'
  AND timestamp > NOW() - INTERVAL '1 month'
  AND ciphersuites->>'pfs' != 'None'
GROUP BY ciphersuites->>'pfs'
ORDER BY COUNT(DISTINCT(target)) DESC;
