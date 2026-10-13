# safe-open
Automated static-analysis sandbox that scans PDFs, Office files and zips for threats before you open them.

The application should let a user select a PDF, Office document, or ZIP archive and analyse it without opening or executing the file normally.

It will inspect the file for suspicious characteristics and produce a report explaining the findings.
For example:
- A PDF contains suspicious JavaScript or automatic actions.
- A Word document contains macros.
- A ZIP archive contains a potentially dangerous executable or path traversal filename.
- A file has a misleading extension or an unusually high-risk combination of indicators.
Important: this will be a static-analysis tool, not a guarantee that a file is safe. A clean scan cannot prove that a file contains no malware.