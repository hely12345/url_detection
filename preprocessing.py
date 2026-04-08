import pandas as pd

# pd.set_option('display.max_rows', None)
# pd.set_option('display.max_columns', None)
# pd.set_option('display.max_colwidth', None) # Also set column width to avoid content truncation
# pd.set_option('display.width', 1000) 

df = pd.read_csv('Features_extracted.csv')


df = df.fillna({'domain_length':0})
df.to_csv('ready.csv')

# print(pd.crosstab(df['is_ip_based'], df['type'], normalize='index') * 100)
# print(list(df['at_count'].unique()))
