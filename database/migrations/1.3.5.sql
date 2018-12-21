ALTER TABLE certificates RENAME COLUMN sha256_subject_spki TO sha256_spki;
ALTER TABLE certificates ADD COLUMN sha256_subject_spki varchar;
