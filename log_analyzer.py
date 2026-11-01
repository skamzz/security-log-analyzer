import re
import csv

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

def parse_log_line(line):
    ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
    timestamp_pattern = r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'

    ip = re.search(ip_pattern, line)
    timestamp = re.search(timestamp_pattern, line)

    if ip:
        ip = ip.group()

    if timestamp:
        timestamp = timestamp.group()

    if "Invalid user" in line:
        event_type = "invalid_user"
    elif "Failed password" in line and "invalid user" not in line:
        event_type = "failed_password"
    elif "POSSIBLE BREAK-IN ATTEMPT" in line:
        event_type = "break_in_attempt"
    elif "Received disconnect" in line:
        event_type = "disconnect"
    elif "Connection closed by" in line:
        event_type = "connection_closed"
    else:
        event_type = None

    return ip, timestamp, event_type


def analyzer(log_lines, threshold=5):
    ip_data = {}
    suspicious_ips = {}

    for line in log_lines:
        ip, timestamp, event_type = parse_log_line(line)

        if ip is None or event_type is None:
            continue

        if ip not in ip_data:
            ip_data[ip] = {
                'total_attempts': 0,
                'failed_logins': 0,
                'invalid_user': 0,
                'failed_password': 0,
                'break_in_attempt': 0,
                'disconnect': 0,
                'connection_closed': 0,
                'first_seen': timestamp,
                'last_seen': timestamp
            }

        ip_data[ip]["last_seen"] = timestamp

        if event_type in ["invalid_user", "failed_password", "break_in_attempt"]:
            ip_data[ip]["total_attempts"] += 1

        if event_type in ["invalid_user", "failed_password"]:
            ip_data[ip]["failed_logins"] += 1

        if event_type == "invalid_user":
            ip_data[ip]["invalid_user"] += 1
        elif event_type == "failed_password":
            ip_data[ip]["failed_password"] += 1
        elif event_type == "break_in_attempt":
            ip_data[ip]["break_in_attempt"] += 1
        elif event_type == "disconnect":
            ip_data[ip]["disconnect"] += 1
        elif event_type == "connection_closed":
            ip_data[ip]["connection_closed"] += 1

    for ip, data in ip_data.items():
        if data["total_attempts"] >= threshold:
            if data["failed_logins"] >= (threshold * 2):
                risk_level = "Critical"
            elif data["failed_logins"] >= threshold:
                risk_level = "High"
            elif data["failed_logins"] > 0:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            risk_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
            data["risk_level"] = risk_level
            data["risk_order"] = risk_order[risk_level]
            suspicious_ips[ip] = data

    return suspicious_ips


def daily_analyzer(log_lines):
    daily_data = {}

    for line in log_lines:
        parsed = parse_log_line(line)
        _, timestamp, event_type = parsed

        if timestamp is None or event_type is None:
            continue

        month, day = timestamp.split()[:2]
        daily = f"{month} {day}"

        if daily not in daily_data:
            daily_data[daily] = {
                'date': daily,
                'sort_key': MONTHS[month] * 100 + int(day),
                'total_events': 0,
                'failed_logins': 0 
            }

        if event_type in ["invalid_user", "failed_password", "break_in_attempt"]:
            daily_data[daily]["total_events"] += 1

        if event_type in ["invalid_user", "failed_password"]:
            daily_data[daily]["failed_logins"] += 1

    return daily_data


if __name__ == "__main__":
    with open("auth.log/auth.log", "r") as file:
        log_lines = file.readlines()

    result = analyzer(log_lines)
    daily_result = daily_analyzer(log_lines)

    with open("results/suspicious_ips.csv", "w", newline="", encoding="utf-8") as file:
        write = csv.writer(file)
        write.writerow(["ip", "total_attempts", "failed_logins", "first_seen", "last_seen", "risk_level", "risk_order"])
        for ip, data in result.items():
            write.writerow([ip, data["total_attempts"], data["failed_logins"], data["first_seen"], data["last_seen"], data["risk_level"], data["risk_order"]])

    with open("results/daily_events.csv", "w", newline="", encoding="utf-8") as file:
        write = csv.writer(file)
        write.writerow(["date", "sort_key", "total_events", "failed_logins"])
        for date, data in daily_result.items():
            write.writerow([data["date"], data["sort_key"], data["total_events"], data["failed_logins"]])

    with open("results/ip_event_breakdown.csv", "w", newline="", encoding="utf-8") as file:
        write = csv.writer(file)
        write.writerow(["ip", "invalid_user", "break_in_attempt", "disconnect"])
        for ip, data in result.items():
            write.writerow([ip, data["invalid_user"], data["break_in_attempt"], data["disconnect"]])

    with open("results/connection_breakdown.csv", "w", newline="", encoding="utf-8") as file:
        write = csv.writer(file)
        write.writerow(["ip", "disconnect", "connection_closed"])
        for ip, data in result.items():
            write.writerow([ip, data["disconnect"], data["connection_closed"]])