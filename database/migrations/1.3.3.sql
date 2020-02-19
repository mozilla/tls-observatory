ALTER TABLE certificates ADD COLUMN x509_extendedKeyUsageOID jsonb NULL;
UPDATE certificates SET x509_extendedkeyusageoid = '[]'::jsonb WHERE x509_extendedkeyusageoid IS NULL;

ALTER TABLE certificates ADD COLUMN mozillaPolicyV2_5 jsonb NULL;
UPDATE certificates SET mozillaPolicyV2_5 = '{}'::jsonb WHERE mozillaPolicyV2_5 IS NULL;
