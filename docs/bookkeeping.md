# Sunnymead Group bookkeeping workspace

## Use the books

Open /admin/ and sign in through Google. Select Sunnymead Web to manage its records or All trading names to view company-wide figures.

The existing data KV key remains Sunnymead Web's book. It is not cleared, replaced or moved. Other trading names store independent data under books:<venture-id>. The books_ventures key holds the company details and trading-name list.

Only Sunnymead Web is initially listed. Murv's Bar is an example of a future venture; it has not been added or populated with sample transactions. Use Add trading name when ready, with a unique invoice prefix and either Active or Planned status. Status can be changed in Trading name settings.

## Transactions

Record money in or out, entry date, gross amount, category, customer/supplier, payment status/date, due date, bank/cash account name, manually entered VAT, statement matching and a receipt/document reference.

Expenses can be unpaid bills. A statement match requires a paid transaction. Asset movements, capital/loans/owner funding, and internal transfers are excluded from trading activity totals. Enter both sides of internal transfers under that treatment where appropriate.

Receipt references are text references to documents kept elsewhere; the workspace does not upload receipts or connect to bank feeds.

Existing paid expenses stay paid. Unknown historic payment dates are left blank. Reports use entry dates; payment totals include entries marked paid and are not a payment-date-based statutory cash-basis calculation.

## Invoices

Create a general customer invoice under the selected trading name. Website build/care invoices remain available in Sunnymead Web's Projects tab.

Each invoice creates one unpaid income entry. Marking it paid updates that entry. The legacy monthly-fee action has been retired to avoid creating another record for the same income. Previously entered duplicate fee records, if any, should be reviewed rather than automatically deleted.

New invoices snapshot issuer details, include the registered company name, and use a unique trading-name invoice prefix. Add the real company number, registered address and financial year start in Company details; set contact and payment details for each trading name in Settings. Old invoices without an issuer snapshot use the current settings.

Invoice amounts/dates cannot be altered through the linked transaction, and the linked transaction cannot be deleted separately.

## Reports and records

Set a date range for transaction reports, invoices and CSV exports. This calendar year and This financial year provide shortcuts; financial year uses the company's configured start.

Reports show recorded gross trading activity, paid trading activity, unpaid income/bills, and separate asset, financing and transfer movements. VAT is entered manually and is not calculated as a return or as recoverable VAT. Export transactions for your accountant.

The combined company view is read-only for transactions; select the appropriate trading name to edit its book. Company backup downloads all books, company metadata and stored change history as JSON.

Transaction, invoice, project, reminder and invoice-setting changes save a before/after record with timestamp and signed-in email. This is a practical change history, not a tamper-proof audit service. Company detail and venture registry edits are not in the per-book history.

## Scope and storage

This workspace is for bookkeeping and accountant exports. It does not prepare or submit statutory accounts, Corporation Tax returns or VAT/MTD returns, run payroll, calculate depreciation, or provide a complete double-entry general ledger and balance sheet.

Storage continues to use the site's Cloudflare KV. KV is eventually consistent and the current read/modify/write approach does not provide transactional locking. Avoid simultaneous edits from multiple tabs/devices; a transactional database is needed before expanding to concurrent staff use. Invoice sequencing has duplicate checks but cannot guarantee uniqueness during concurrent writes.

Change history grows inside each book's KV value, so monitor storage and export backups regularly. Do not treat this as the sole document archive.
