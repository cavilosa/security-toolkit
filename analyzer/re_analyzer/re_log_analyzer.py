'''
python re_log_analyzer.py -l "2025-06-11 user: admin123 from 10.0.0.1 ERROR: failed login" -e output.json
python re_log_analyzer.py --file logs.txt --export output.json
python re_log_analyzer.py --log "2025-06-11 user: admin123 from 10.0.0.1 ERROR: failed login" --export output.json
python re_log_analyzer.py  -f results -e='results-export'
'''
import os
import re
import json
import sys
import logging
import argparse
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def extract_ip_addresses(log_line):
    try:
        pattern = r'\d+\.\d+\.\d+\.\d+'
        ips = re.findall(pattern, log_line)
        logging.info(f"Extracted IP addresses: {ips} from log line: {log_line}")
        return ips
    except Exception as e:
        logging.error(f"Error extracting IP addresses: {e}, log_line {log_line})")
        return []


def extract_dates(log_line):
    '''Find all dates in the format YYYY-MM-DD:'''
    try:
        pattern = r'\d{4}\-\d{2}\-\d{2}'
        dates = re.findall(pattern, log_line)
        logging.info(f"Extracted dates: {dates} from log line: {log_line}")
        return dates

    except Exception as e:
        logging.error(f"Error extracting dates: {e}, log_line {log_line})")
        return []
    

def match_error_lines(log_line):
    '''Match any line that starts with 'ERROR' and return the matched lines'''
    try:
        pattern = r'\bERROR\b.*'           
        error_lines = re.findall(pattern, log_line)
        logging.info(f"Matched error lines: {error_lines} from log line: {log_line}")
        return error_lines
    
    except Exception as e:
        logging.error(f"Error matching error lines: {e}, log_line {log_line})")
        return []


# 4.	Exercise 4:
def extract_username(log_string):
    """Extract the username from:"""
    try:
        pattern = r'user:\s*(\w+)'
        user_names = re.findall(pattern, log_string)
        logging.info(f" Extracted Usernames {user_names}.")
        return user_names
    
    except Exception as error:
        logging.error(f"{error}. Failed to extract username from {log_string}")
        return []


def hide_numbers(log_line):
    """Replace all digits in the string with '*'"""
    try:
        pattern = r'\d'
        new_log = re.sub(pattern, "*", log_line)
        logging.info(f" New log line ready {new_log}")
        return new_log
    except Exception as e:
        logging.error(f" Error in replace digits {e}, line - {log_line}")


def export_results(file, data):
    ''' Export results to a file adding the date and time to the name for historical purposes. '''
    try:
        date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        final_path = f"{file} - {date}"

        os.makedirs(os.path.dirname(final_path), exist_ok=True)

        with open(final_path, "w", encoding='UTF-8') as f:
            json.dump(data, f, indent=4)
            logging.info(f"Successfully exported the data to {file}")
        return True
    except Exception as e:
        logging.error(f" Failed to export data: {e}")
        return False


def get_data(line):
    ''' Get all data for a line either from a file or just one log'''
    try:
        all_ips, all_dates, all_errors, all_users = [], [], [], []
        safe_lines = []

        all_ips.extend(extract_ip_addresses(line))
        all_dates.extend(extract_dates(line))
        all_errors.extend(match_error_lines(line))
        all_users.extend(extract_username(line))
        safe_lines.append(hide_numbers(line))
        return all_ips, all_dates, all_errors, all_users, safe_lines
    except Exception as e:
        logging.error(f"Error on gettind data for the line {line}, {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Log Analyzer')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--log', '-l', metavar='log line',
                        required=False, type=str, help='Log to analyze')
    group.add_argument("--file", '-f', metavar='Logs file', required=False, 
                       type=str, help='File with logs')
    parser.add_argument('--export', '-e', metavar='your-file-name.json', type=str, 
                        required=False, help='Provide file name for exporting the results.')
    args = parser.parse_args()

    all_ips, all_dates, all_errors, all_users = [], [], [], []
    safe_lines = []

    if args.file:
        if not os.path.isfile(args.file):
            logging.error(f"File not found: {args.file}")
            sys.exit(1)
        with open(args.file, 'r', encoding='UTF-8') as file:
            for line in file:
                ips, dates, errors, users, safe = get_data(line)
                all_ips.extend(ips)
                all_dates.extend(dates)
                all_errors.extend(errors)
                all_users.extend(users)
                safe_lines.extend(safe)

    if args.log:
        log_line = args.log
        all_ips, all_dates, all_errors, all_users, safe_lines = get_data(log_line)

    if args.export:
        results = {
            "ip_addresses": all_ips,
            "dates": all_dates,
            "errors": all_errors,
            "usernames": all_users,
            "safe_log_lines": safe_lines
        }

        export_results(args.export, results)

