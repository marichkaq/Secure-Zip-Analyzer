# Secure-Zip-Analyzer
Overview:

This tool processes password-protected zip files by decrypting them, analyzing the contents, and generating a detailed report. 
It uses a password collection to unlock the zip file, lists all contained files, and performs a series of analyses.

Features:

File Handling:

Accepts only .zip files.
Identifies and uses passwords from a provided collection to decrypt the zip file.

Analysis:

Generates SHA-256 checksums for all files.
Queries VirusTotal for file evaluations.
Searches .txt and .pdf files for keywords: PESEL, password, and email addresses.
Counts occurrences of keywords and lists unique email addresses.

Report Generation:

Compiles an aggregate report of the analysis.
Generates and saves an SHA-256 checksum for the report.

Packaging: 

Repackages the original files, report, and checksum into a new password-protected zip file.

Logging:

Logs each execution step into a log.txt file.

Usage:

Setup:

Ensure you have the necessary Python libraries installed:
pip install zipfile PyPDF2 requests
Update the code with your VirusTotal API key by replacing 'your_api_key' with your actual key.

Execution:

Run the program: python zip_decryptor.py.
Provide the zip file path and password collection file when prompted.
