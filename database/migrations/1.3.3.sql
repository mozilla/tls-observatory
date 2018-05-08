ALTER TABLE certificates ADD COLUMN x509_extendedKeyUsageOID jsonb NULL;
ALTER TABLE certificates ADD COLUMN mozillaPolicyV2_5 jsonb NULL;