import csv
import subprocess
import re

reader = csv.reader(open('group.csv', newline='', encoding='utf-8'))
for row in reader:
    domain = row[0]
    group = row[1]
    # print(row)
    print(f"{domain} -> {group}")

print('--------')
