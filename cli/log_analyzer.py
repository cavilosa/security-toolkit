# log_analyzer.py
import sys
import os
import argparse
import logging

def load_log_file(path):
    '''Open the file and read lines'''
    try:
        with open(path, 'r') as file:
            lines = file.readlines()
            logging.info(f"Loaded {len(lines)} lines from {path}")
            return lines
    except FileNotFoundError:
        logging.error(f"File not found: {path}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    sys.exit(1) 


def filter_logs(lines, keyword):
    '''Match lines with the keyword'''
    try:
        if not keyword:
            logging.warning("No keyword provided, returning all lines")
            return lines
        keyword_lower = keyword.lower()
        filtered_lines = [line for line in lines if keyword_lower in line.lower()]
        logging.info(f"Found {len(filtered_lines)} lines containing '{keyword}'")
        return filtered_lines

    except Exception as e:
        logging.error(f"Error filtering logs: {e}")
    sys.exit(1)


def save_results(lines, out_path):
    ''' Write filtered lines to output file '''
    if not out_path:
            logging.warning("No output path provided, results will not be saved")
            return
    if not lines:
        logging.info("No lines to save")
        return
    try:    
        logging.info(f"Saving {len(lines)} lines to {out_path}")
        with open(out_path, 'w') as file:
            for line in lines:
                file.write(line.rstrip('\n') + '\n')  # ensures no double newlines
                return out_path
    except Exception as e:
        logging.error(f"Error saving results to '{out_path}': {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analyzer CLI Tool")
    parser.add_argument('--log_file', '-f', type=str, help='Path to the log file to analyze')
    parser.add_argument('--output_file', '-o', type=str, nargs='?', default=None,
                         help='Path to save the filtered results')
    parser.add_argument('--keyword', '-k', type=str, default=None,
                        help='Keyword to filter log lines')
    args = parser.parse_args()

    try:
        lines = load_log_file(args.log_file)
        filtered_lines = filter_logs(lines, args.keyword)
        saved_output = save_results(filtered_lines, args.output_file[0] if args.output_file else None)

    except Exception as e:
        logging.error(f"Error in main execution: {e}")
        sys.exit(1)
