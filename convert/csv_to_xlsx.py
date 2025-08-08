import pandas as pd

csv_file = '/Users/dragonfly/Documents/scan_ip/data/Book1.csv'
xlsx_file = '/Users/dragonfly/Documents/scan_ip/data/Book1-copy.xlsx'
df = pd.read_csv(csv_file)
df.to_excel(xlsx_file, index=False, engine='openpyxl')
