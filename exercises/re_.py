'''
python log_analyzer.py -l "2025-06-11 user: admin123 from 10.0.0.1 ERROR: failed login" -e output.json

'''
import re
import json
import logging
import argparse

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


# 5.	Exercise 5:
def hide_numbers(log_line):
    """Replace all digits in the string with '*'"""
    try:
        pattern = r'\d'
        new_log = re.sub(pattern, "*", log_line)
        logging.info(f" New log line ready {new_log}")
        return new_log
    except Exception as e:
        logging.error(f" Error in replace digits {e}, line - {log_line}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Log Analyzer')
    parser.add_argument('--log', '-l', metavar='log',
                        required=True, type=str, help='Log to analyze')
    parser.add_argument('--export', '-e', metavar='your-file-name.json', type=str, 
                        required=False, help='Provide file name for exporting the results.')
    args = parser.parse_args()
    if args.log:
        log_line = args.log
        # Extract IP addresses from the provided log line
        ip_addresses = extract_ip_addresses(log_line)
        # Extract dates from the provided log line
        dates = extract_dates(log_line)
        # Match error lines from the provided log line
        errors = match_error_lines(log_line)
        # Extract usernames 
        users = extract_username(log_line)
        # Replace numbers by asterisks
        safe_line = hide_numbers(log_line)

        print(f"IPs: {ip_addresses}")
        print(f"Dates: {dates}")
        print(f"Errors: {errors}")
        print(f"Usernames: {users}")
        print(f"Safe Line: {safe_line}")

        if args.export:
            data = dict()
            data.update({
                'ip_addresses': ip_addresses,
                'dates': dates, 
                'errors': errors,
                'users':users,
                'safe_line': safe_line
            })

            try:
                with open(args.export, "w", encoding='UTF-8') as file:
                    json.dump(data, file, indent=4)
                    logging.info(f"Successfully exported the data to {args.export}")
            except Exception as e:
                logging.error(f" Failed to export data: {e}")


