import argparse
import re
import json
import os
import platform
import pyfiglet
import csv
from collections import defaultdict, Counter
from colorama import Fore, Style


def print_section_header(title):
    print(f"\n{Fore.CYAN}{title}\n{'----->'}{Style.RESET_ALL}")


def print_colored(text, color=Fore.WHITE, style=Style.RESET_ALL):
    return f"{style}{color}{text}{Style.RESET_ALL}"


def prompt_for_file():
    while True:
        file_path = input(
            "Please enter full path to your .log or .txt file: ").strip()
        if os.path.exists(file_path) and file_path.lower().endswith(('.log', '.txt')):
            return file_path
        print("Invalid file. Please enter a valid .log or .txt file.")


print('\n' + print_colored(pyfiglet.figlet_format("Log Analyzer",
      font='slant'), Fore.GREEN, Style.BRIGHT))

# Regex patterns for different log types
LOG_PATTERNS = {
    "SSH": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port"),
    "APACHE": re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST|PUT|DELETE) (.*?) HTTP/.*" (\d+) (\d+)'),
    "WINDOWS": re.compile(r'EventID=(\d+).*User=(\S+).*Source=(\S+)'),
}


def detect_log_type(file_path):
    """Detects the log type by scanning the first 50 lines of the file."""
    log_counts = Counter()

    try:
        with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as log_file:
            for _ in range(50):  # Scan first 50 lines
                line = log_file.readline()
                if not line:
                    break  # Stop if the file is shorter than 50 lines

                for log_type, pattern in LOG_PATTERNS.items():
                    if pattern.search(line):
                        log_counts[log_type] += 1  # Count matches

        if log_counts:
            # Return the most common match
            return log_counts.most_common(1)[0][0]

    except Exception as e:
        print(f"Error detecting log type: {e}")

    return "UNKNOWN"


def parse_log(file_path, log_type):
    failed_attempts = defaultdict(int)
    log_entries = Counter()
    skipped_lines = 0

    try:
        with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as log_file:
            for line in log_file:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 2:
                    skipped_lines += 1
                    continue

                key = parts[0].replace('\u0000', '').strip()
                key = key if key else "[Unknown Entry]"
                log_entries[key] += 1

                match = LOG_PATTERNS.get(
                    log_type, re.compile(r'')).search(line)
                if match:
                    if log_type == "SSH":
                        user, ip = match.groups()
                        failed_attempts[ip] += 1
                    elif log_type == "APACHE":
                        ip, _, method, _, status, _ = match.groups()
                        failed_attempts[ip] += 1 if status.startswith(
                            "4") or status.startswith("5") else 0
                    elif log_type == "WINDOWS":
                        event_id, user, source = match.groups()
                        failed_attempts[user] += 1
    except FileNotFoundError:
        print("Error: Log file not found.")
        return {}, Counter(), 0
    except PermissionError:
        print("Error: Permission denied. Try running with elevated privileges.")
        return {}, Counter(), 0
    except Exception as e:
        print(f"Error reading log file: {e}")
        return {}, Counter(), 0

    return failed_attempts, log_entries, skipped_lines


def display_results(log_entries, failed_attempts, skipped_lines):
    """Allows user to choose between graph or text output with a combined design."""
    while True:
        choice = input(
            f"Would you like to see results as (1) Graph or (2) Text? \nEnter 1 or 2: ").strip()
        if choice == "1":
            print_section_header("Graph Output")
        elif choice == "2":
            print_section_header("Text Output")
        else:
            print("Invalid choice. Please enter 1 for Graphs or 2 for Text.")
            continue

        print_section_header("Log Entry Frequency")
        if log_entries:
            max_label_length = max(len(label) for label in log_entries.keys())
            max_count = max(log_entries.values())
            for label, count in log_entries.most_common(10):
                bar = "*" * int((count / max_count) * 40)
                print(f"{label.ljust(max_label_length)} | {bar} {count}" if choice ==
                      "1" else f"{label}: {count} occurrences")
        else:
            print("No log entry data found.")

        print_section_header("Failed Login Attempts")
        if failed_attempts:
            max_label_length = max(len(ip) for ip in failed_attempts.keys())
            max_count = max(failed_attempts.values())
            for ip, count in failed_attempts.most_common(5):
                bar = "*" * int((count / max_count) * 40)
                print(f"{ip.ljust(max_label_length)} | {bar} {count}" if choice ==
                      "1" else f"{ip}: {count} failed attempts")
        else:
            print("No failed login attempts detected.")

        print_section_header("Top Attack Sources")
        if failed_attempts:
            max_label_length = max(len(ip) for ip in failed_attempts.keys())
            max_count = max(failed_attempts.values())
            for ip, count in failed_attempts.most_common(5):
                bar = "*" * int((count / max_count) * 40)
                print(f"{ip.ljust(max_label_length)} | {bar} {count}" if choice ==
                      "1" else f"{ip}: {count} failed attempts")
        else:
            print("No attack sources detected.")

        print_section_header("Malformed Lines")
        if skipped_lines > 0:
            bar = "*" * min(40, skipped_lines // 5)
            print(f"Malformed Lines | {bar} {skipped_lines}" if choice ==
                  "1" else f"Malformed lines encountered: {skipped_lines} ")
        else:
            print("No malformed lines found.")

        break


def save_report(data, log_entries, skipped_lines, output_format):
    """Saves the parsed data to a file in the specified format."""
    output_file = f"logAnalyzer_Output.{output_format}"

    if not data and not log_entries:
        print("No significant log data detected.")
        return

    clean_log_summary = Counter(
        {key.replace('\u0000', ''): value for key, value in log_entries.items()})

    report_content = {
        "failed_logins": data if data else "None detected",
        "top_attack_ips": dict(data.most_common(5)) if data else "None detected",
        "log_summary": dict(clean_log_summary.most_common(10)),
        "skipped_lines": skipped_lines
    }

    with open(output_file, 'w') as f:
        if output_format == 'json':
            json.dump(report_content, f, indent=4)
        elif output_format == 'text':
            f.write("---------> Log Analysis Report <---------\n")
            f.write("\n========== Failed Login Attempts ==========")
            f.write("\nNone detected\n" if not data else "\n".join(
                f"{ip}: {count} failed attempts" for ip, count in data.items()))
            f.write("\n========== TOP ATTACK SOURCES ==========")
            f.write("\nNone detected\n" if not data else "\n".join(
                f"{ip}: {count} failed attempts" for ip, count in data.items()))
            f.write("\n========== Top 10 Log Entries ==========\n")
            f.write("\n".join(f"{entry}:{count} occurrences" for entry,
                    count in clean_log_summary.most_common(10)))
            f.write(f"\n\n========== Skipped Malformed Lines ==========\n")
            f.write(f"{skipped_lines} lines skipped due to formatting issues.")
        print(
            f"{Style.BRIGHT}{Fore.CYAN}Report saved as: {Style.RESET_ALL}{output_file}")


def save_as_csv(failed_attempts, log_entries, skipped_lines, output_format):
    output_file = f"logAnalyzer_Output.{output_format}"

    with open(output_file, 'w', newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Category", "Value", "Count"])

        for entry, count in log_entries.items():
            writer.writerow(["Log Entry", entry, count])

        for ip, count in failed_attempts.items():
            writer.writerow(["Failed Login", ip, count])

        writer.writerow(["Malformed Lines", "N/A", skipped_lines])

    print(f"Report saved as {output_file}")


def main():
    log_file = prompt_for_file()
    log_type = detect_log_type(log_file)
    print_section_header(f"Detected Log Type: {log_type}")

    failed_attempts, log_entries, skipped_lines = parse_log(log_file, log_type)
    display_results(log_entries, failed_attempts, skipped_lines)

    attempts = 0
    while attempts < 3:
        save_prompt = input(
            "\nWould you like to save the report? (yes/no): ").strip().lower()
        if save_prompt in ["yes", "y"]:
            while attempts < 3:
                format_choice = input(
                    "Choose format - 'text', 'csv' or 'json': ").strip().lower()
                if format_choice in ["text", "json"]:
                    save_report(failed_attempts, log_entries,
                                skipped_lines, format_choice)
                    break
                elif format_choice == "csv":
                    save_as_csv(failed_attempts, log_entries,
                                skipped_lines, format_choice)
                    break
                else:
                    print("Invalid choice. Please enter 'text', 'csv' or 'json'.")
                    attempts += 1
            break
        elif save_prompt in ["no", "n"]:
            print("Report will not be saved.")
            break
        else:
            print("Invalid choice. Please enter 'yes' or 'no'.")
            attempts += 1

    if attempts >= 3:
        print("Get it together. Exiting...")

    print(print_colored(f"\nAnalysis complete.\n", Fore.YELLOW, Style.BRIGHT))


if __name__ == "__main__":
    main()
