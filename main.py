import csv
import subprocess
import re
import pandas as pd
import os
import time

output_string = ''
output_failed = ''
time_delay = 0
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
    
def check_ip_group(ip):
    reader = csv.reader(open('group.csv', newline='', encoding='utf-8'))
    for row in reader:
        prefix = row[0]
        group = row[1]
        if ip.startswith(prefix):
            return f',{group}'
    return ',Unknown'
        
def check_ip_group(ip):
    reader = csv.reader(open('group.csv', newline='', encoding='utf-8'))
    for row in reader:
        prefix = row[0]
        group = row[1]
        if ip.startswith(prefix):
            return f',{group}'
    return ',Unknown'


def check_ip_group_v2(ip):
    reader = csv.reader(open('group.csv', newline='', encoding='utf-8'))
    for row in reader:
        prefix = row[0]
        group = row[1]
        if ip.startswith(prefix):
            return f'{group}'
    return 'Unknown'

def check_cross_ip(ip1, ip2, ip3, ip4):
    if (ip1 == ip2) and (ip1 == ip3) and (ip1 == ip4):
        return False
    else:
        return True
def compare_ip_groups(gip1, gip2, gip3, gip4):
    if gip1 == gip2 and gip1 == gip3 and gip1 == gip4:
        return True
    else:
        return False


def get_cidr_from_ip(ip):
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True)
        output = result.stdout

        # Ưu tiên lấy CIDR
        cidr_match = re.search(r"CIDR:\s*([\d\./,\s]+)", output, re.IGNORECASE)
        if cidr_match:
            # Trường hợp có nhiều CIDR, lấy cái đầu tiên
            cidr = cidr_match.group(1).split(",")[0].strip()
            return cidr

        # Nếu không có CIDR thì lấy route
        route_match = re.search(r"route:\s*([\d\.]+\/\d+)", output, re.IGNORECASE)
        if route_match:
            return route_match.group(1)

        return None

    except Exception as e:
        return f"Lỗi: {e}"

def valid_domain(domain):
    if not isinstance(domain, str) or domain.strip() == '' or domain.lower() == 'nan':
        return False
    return True

def write_output_to_file(output_string, output_path):
    
    file_exists = os.path.exists(output_path)
    
    with open(output_path, 'a', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)

        if not file_exists:
            writer.writerow(['App Domain1', 'App Domain2', 'WebDomain1', 'WebDomain2', 'status'])
        
        for line in output_string.strip().split('\n'):
            row = [col.strip() for col in line.split(',')]
            writer.writerow(row)
            

def scan_ip(reader):
    global output_string, output_failed
    for row in reader:
        domain1 = row[17]
        domain2 = row[18]
        domain3 = row[19]
        domain4 = row[20]
        print("Checking valid domain....")
        if not valid_domain(domain1) and not valid_domain(domain2) and not valid_domain(domain3) and not valid_domain(domain4):
            continue
            print("Checked valid domain")
        try:
            result = subprocess.run(['ping', '-c', '1', domain1], capture_output=True, text=True, timeout=2)
            time.sleep(time_delay)
            result2 = subprocess.run(['ping', '-c', '1', domain2], capture_output=True, text=True, timeout=2)
            time.sleep(time_delay)
            result3 = subprocess.run(['ping', '-c', '1', domain3], capture_output=True, text=True, timeout=2)
            time.sleep(time_delay)
            result4 = subprocess.run(['ping', '-c', '1', domain4], capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and result2.returncode == 0 and result3.returncode == 0 and result4.returncode == 0:
                match = re.search(r'\(([\d\.]+)\)', result.stdout)
                match2 = re.search(r'\(([\d\.]+)\)', result2.stdout)
                match3 = re.search(r'\(([\d\.]+)\)', result3.stdout)
                match4 = re.search(r'\(([\d\.]+)\)', result4.stdout)
                if match and match2 and match3 and match4:
                    ip = match.group(1)
                    ip2 = match2.group(1)
                    ip3 = match3.group(1)
                    ip4 = match4.group(1)
                    group_domain = f"{check_ip_group_v2(ip)},{check_ip_group_v2(ip2)},{check_ip_group_v2(ip3)},{check_ip_group_v2(ip4)}"
                    if compare_ip_groups(check_ip_group_v2(ip), check_ip_group_v2(ip2), check_ip_group_v2(ip3), check_ip_group_v2(ip4)):
                        group_domain += ',NonCross'
                    else:
                        group_domain += ',Cross'

                else:
                    print(f"{domain1} -> No IP found")
            else:
                output_failed += f"{domain1},NotExist\n"
            # print(group_domain)
            write_output_to_file(group_domain, 'output.csv')        
        except Exception as e:
            print(f"{domain1} -> Error: {e}")



# main

if detect_file_type(file_path) == 'xlsx':
    df = pd.read_excel(file_path)
    reader_xlsx = df.values.tolist()
    scan_ip(reader_xlsx)
elif detect_file_type(file_path) == 'csv':
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader_csv = csv.reader(csvfile)
        scan_ip(reader_csv)



    

