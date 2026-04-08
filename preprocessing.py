import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', None) # Also set column width to avoid content truncation
pd.set_option('display.width', 1000) 

df = pd.read_csv('Features_extracted_final.csv')

# df = df.fillna({'domain_length':0})
# print(df.info())
print(df[['DomainAgeDays', 'DomainRegLength']].isnull().sum())
print(f"Total rows: {len(df)}")
df.fillna({'DomainAgeDays':-1},inplace=True)
df.fillna({'DomainRegLength':-1},inplace=True)
df.to_csv('ready_final.csv')

# print(pd.crosstab(df['is_ip_based'], df['type'], normalize='index') * 100)
# print(list(df['at_count'].unique()))

