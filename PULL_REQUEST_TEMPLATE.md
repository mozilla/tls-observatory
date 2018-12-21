<Describe your changes here, add references to any issue>

## Checklist
* [ ] Run `make`, `gofmt` and `golint` your code, and run a test scan on your local machine before submitting for review.
* [ ] Workers needs an AnalysisPrinter, registered via `worker.RegisterPrinter()` (which is separate from `worker.RegisterWorker()`), and imported in [tlsobs](https://github.com/mozilla/tls-observatory/blob/master/tlsobs/main.go#L20-L28) ([example](https://github.com/mozilla/tls-observatory/blob/master/worker/awsCertlint/awsCertlint.go#L39-L56)).
* [ ] When adding new columns to the database, also add a DB migration script under `database/migrations` named the **next** release (eg. if current release is 1.3.2, migration file will be `1.3.3.sql`).
* [ ] When new columns require data to be recomputed, add a script under `/tools` ([example](https://github.com/mozilla/tls-observatory/blob/master/tools/fixSHA256SubjectSPKI.go)) that updates the database and will be run by administrators.
