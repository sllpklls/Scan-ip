import csv
import subprocess
import re
import pandas as pd
import os

output_string = ''
output_failed = ''
file_path = '/Users/dragonfly/Documents/scan_ip/data/Book1.xlsx'

def detect_file_type(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext == '.csv':
        return 'csv'
    elif ext in ['.xlsx', '.xls']:
        return 'xlsx'
    else:
        return 'unknown'

# def check_ip_group(reader):
#     for row in reader:
#         prefix = row[0]
#         group = row[1]
#         if ip.startswith(prefix):
#             return f',{group}' 
#     return ',Unknown'
def check_ip_group(ip):
    reader = csv.reader(open('group.csv', newline='', encoding='utf-8'))
    for row in reader:
        prefix = row[0]
        group = row[1]
        if ip.startswith(prefix):
            return f',{group}'

    # if ip.startswith("103.159.50."):
    #     return ',DA'
    # if ip.startswith("142.250.198."):
    #     return ',DB'
    return ',Unknown'

def valid_domain(domain):
    if not isinstance(domain, str) or domain.strip() == '' or domain.lower() == 'nan':
        return False
    return True

def scan_ip(reader):
    global output_string, output_failed
    for row in reader:
        domain1 = row[17]
        domain2 = row[18]
        if not valid_domain(domain1) and not valid_domain(domain2):
            continue
        try:
            result = subprocess.run(['ping', '-c', '1', domain1], capture_output=True, text=True, timeout=2)
            result2 = subprocess.run(['ping', '-c', '1', domain2], capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and result2.returncode == 0:
                match = re.search(r'\(([\d\.]+)\)', result.stdout)
                match2 = re.search(r'\(([\d\.]+)\)', result2.stdout)
                if match and match2:
                    ip = match.group(1)
                    ip2 = match2.group(1)
                    print(f"{domain2} -> {ip2}")
                    output = f"{domain1},{ip}"
                    output += check_ip_group(ip)
                    output_string += output + '\n'
                else:
                    print(f"{domain1} -> No IP found")
            else:
                output_failed += f"{domain1},NotExist\n"
        except Exception as e:
            print(f"{domain1} -> Error: {e}")

if detect_file_type(file_path) == 'xlsx':
    df = pd.read_excel(file_path)
    reader_xlsx = df.values.tolist()
    scan_ip(reader_xlsx)
elif detect_file_type(file_path) == 'csv':
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader_csv = csv.reader(csvfile)
        scan_ip(reader_csv)


csv_file_path = 'domain.csv'



print(output_string, end='') 
print('--------')
print(output_failed, end='')
# with open('output.csv', 'w', newline='', encoding='utf-8') as outfile:
#     writer = csv.writer(outfile)
#     writer.writerow(['domain', 'ip', 'group'])
#     for line in output_string.strip().split('\n'):
#         parts = line.split(',')
#         if len(parts) >= 2:
#             group = parts[2] if len(parts) > 2 else ''
#             writer.writerow([parts[0], parts[1], group])

