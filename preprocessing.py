import pandas as pd

df = pd.read_csv('Features_extracted_final_final.csv')

print(df[['DomainAge', 'DomainEndPeriod']].isnull().sum())
print(f"Total rows: {len(df)}")

df.fillna({'DomainAge': -1}, inplace=True)
df.fillna({'DomainEndPeriod': -1}, inplace=True)

print(df.info())
df.to_csv('ready_final_final.csv')
