import zipfile
import time
import hashlib
import requests
import os
import re
import logging
import tempfile
from PyPDF2 import PdfFileReader
from collections import defaultdict

try:
    import docx
except ImportError:
    docx = None

# Configure logging
logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

class SecureZipAnalyzer:
    def __init__(self, zip_path, password_file, api_key):
        self.zip_path = zip_path
        self.password_file = password_file
        self.api_key = api_key
        self.passwords = self.get_password_list()
        self.extract_path = None
        self.files = []
        self.sha256_checksums = {}
        self.virustotal_results = {}
        self.keyword_counts = {}
        self.malicious_files = []

    def get_password_list(self):
        # Read passwords from file and return as a list
        with open(self.password_file, 'r') as f:
            passwords = f.read().splitlines()
        logging.info(f'Loaded {len(passwords)} passwords from {self.password_file}')
        return passwords

    def extract_zip(self):
        # Attempt to extract zip file with each password until successful
        for password in self.passwords:
            try:
                with zipfile.ZipFile(self.zip_path) as zf:
                    self.extract_path = tempfile.mkdtemp()
                    zf.extractall(path=self.extract_path, pwd=bytes(password, 'utf-8'))
                    logging.info(f'Successfully extracted {self.zip_path} with password {password}')
                    return password
            except RuntimeError:
                logging.warning(f'Failed to extract {self.zip_path} with password {password}')
            except Exception as e:
                logging.error(f'Error extracting {self.zip_path}: {e}')
        logging.error(f'Failed to extract {self.zip_path} with provided passwords')
        return None

    def list_files(self):
        # List all files in the extracted directory
        for root, _, filenames in os.walk(self.extract_path):
            for filename in filenames:
                self.files.append(os.path.join(root, filename))
        logging.info(f'Listed {len(self.files)} files in {self.extract_path}')

    def generate_sha256(self, file_path):
        # Generate SHA-256 checksum for the given file
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            checksum = sha256_hash.hexdigest()
            logging.info(f'Generated SHA-256 checksum for {file_path}')
            return checksum
        except OSError as e:
            logging.error(f'Error generating SHA-256 for {file_path}: {e}')
            return 'Checksum Error'

    def query_virustotal(self, file_hash):
        # Query VirusTotal for the given file hash
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {
            "x-apikey": self.api_key
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                logging.warning(f'File {file_hash} is malicious.')
            logging.info(f'VirusTotal query successful for {file_hash}')
            return data
        else:
            logging.error(f'VirusTotal query failed for {file_hash}: {response.status_code}')
            return None

    def search_keywords(self, file_path, keywords):
        # Search for keywords and extract unique emails in the file
        occurrences = defaultdict(int)
        unique_emails = set()
        if file_path.endswith('.txt'):
            with open(file_path, 'r') as f:
                content = f.read()
        elif file_path.endswith('.pdf'):
            with open(file_path, 'rb') as f:
                reader = PdfFileReader(f)
                content = ''
                for page in range(reader.numPages):
                    content += reader.getPage(page).extractText()
        elif file_path.endswith('.docx') and docx is not None:
            doc = docx.Document(file_path)
            content = ''
            for para in doc.paragraphs:
                content += para.text
        else:
            logging.info(f'Skipping keyword search for {file_path}')
            return occurrences, unique_emails

        for keyword in keywords:
            occurrences[keyword] = len(re.findall(keyword, content, re.IGNORECASE))
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        unique_emails.update(emails)
        logging.info(f'Searched keywords in {file_path}')
        return occurrences, unique_emails

    def generate_report(self):
        # Generate the report file
        report_lines = ["FILE STATUS REPORT\n"]
        for file in self.files:
            status = "Malicious" if file in self.malicious_files else "Clean"
            report_lines.append(f"{file}\t{self.sha256_checksums.get(file, 'No checksum')}\t{self.virustotal_results.get(file, 'No result')}\t{status}\n")

        report_lines.append("\nKEYWORDS REPORT\n")
        for file, counts in self.keyword_counts.items():
            report_lines.append(f"{file}\n")
            for keyword, count in counts['occurrences'].items():
                report_lines.append(f"{keyword}\t{count}\n")
            report_lines.append("Unique Emails:\n")
            for email in counts['emails']:
                report_lines.append(f"{email}\n")

        if self.malicious_files:
            report_lines.append("\nMALICIOUS FILES REPORT\n")
            for file in self.malicious_files:
                report_lines.append(f"{file} is identified as malicious.\n")

        report_content = ''.join(report_lines)
        with open('report.txt', 'w') as f:
            f.write(report_content)
        logging.info(f'Generated report.txt with {len(report_lines)} lines')
        return 'report.txt'

    def process_files(self):
        # Process all files including zip files and identify malicious files
        self.sha256_checksums = {file: self.generate_sha256(file) for file in self.files}
        self.virustotal_results = {}
        self.malicious_files = []
        for file in self.files:
            result = self.query_virustotal(self.sha256_checksums[file])
            if result and result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                self.malicious_files.append(file)
            self.virustotal_results[file] = result

        keywords = ['PESEL', 'password', 'email']
        self.keyword_counts = {}
        for file in self.files:
            occurrences, emails = self.search_keywords(file, keywords)
            self.keyword_counts[file] = {'occurrences': occurrences, 'emails': emails}

    def create_result_zip(self, report_file):
        # Create the result zip file with all files and the report
        report_hash = self.generate_sha256(report_file)

        with open('hash.txt', 'w') as f:
            f.write(report_hash)
        logging.info('Generated hash.txt')

        with zipfile.ZipFile('result.zip', 'w') as zf:
            for file in self.files:
                try:
                    zf.write(file, os.path.basename(file))
                except OSError as e:
                    logging.error(f'Error writing {file} to zip: {e}')
            zf.write(report_file, os.path.basename(report_file))
            zf.write('hash.txt')
            zf.setpassword(b'P4$$w0rd!')
        logging.info('Created result.zip and secured with password')

    def run(self):
        start_time = time.time()
        password = self.extract_zip()
        end_time = time.time()

        if password:
            print(f"Password found: {password} in {end_time - start_time} seconds")
            self.list_files()
            self.process_files()
            report_file = self.generate_report()
            self.create_result_zip(report_file)
            print("Result zip file created and secured with password: P4$$w0rd!")
        else:
            print("Failed to find the password for the zip file.")

if __name__ == '__main__':
    zip_path = input("Enter the path to the zip file: ").strip()
    password_file = '10k-most-common.txt'
    api_key = 'your_api_key'

    analyzer = SecureZipAnalyzer(zip_path, password_file, api_key)
    analyzer.run()
