import csv
import subprocess
import re

csv_file_path = 'domain.csv'

def check_ip_prefix(ip):
    if ip.startswith("103.159.50."):
        return ',DA'
    if ip.startswith("142.250.198."):
        return ',DB'
    return ''

output_string = ''

with open(csv_file_path, newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        # print(row)

        domain = row[0]
        try:
            result = subprocess.run(['ping', '-c', '1', domain], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                match = re.search(r'\(([\d\.]+)\)', result.stdout)
                if match:
                    ip = match.group(1)
                    output = f"{domain},{ip}"
                    output += check_ip_prefix(ip)
                    # if check_ip_prefix(ip):
                    #     output += ',DA'
                    # print(output)
                    output_string += output + '\n'  
                else:
                    print(f"{domain} -> IP not found")
            else:
                print(f"{domain} -> Ping failed")
        except Exception as e:
            print(f"{domain} -> Error: {e}")

print(output_string, end='') 
with open('output.csv', 'w', newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    writer.writerow(['domain', 'ip', 'group'])
    for line in output_string.strip().split('\n'):
        parts = line.split(',')
        if len(parts) >= 2:
            group = parts[2] if len(parts) > 2 else ''
            writer.writerow([parts[0], parts[1], group])