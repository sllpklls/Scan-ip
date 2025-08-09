
import pandas as pd


xlsx_file = '/Users/dragonfly/Documents/scan_ip/data/Book1.xlsx'
csv_file = '/Users/dragonfly/Documents/scan_ip//data/Book1.csv'
df = pd.read_excel(xlsx_file)
df.to_csv(csv_file, index=False)