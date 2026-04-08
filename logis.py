from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score,precision_score,confusion_matrix, mean_absolute_error, mean_squared_error
from sklearn.model_selection import train_test_split,RandomizedSearchCV
from sklearn.tree import export_graphviz
from sklearn.preprocessing import StandardScaler
import pandas as pd
import joblib

data = pd.read_csv('ready.csv')
# print(data.info())

cols = ['Unnamed: 0','domain','type','tld','url']

X = data.drop(cols,axis=1)

y = data['type']

xtr, xtst, ytr, ytst = train_test_split(X,y,test_size=0.2,random_state=1)

scaler = StandardScaler()

xtr = scaler.fit_transform(xtr)
xtst = scaler.transform(xtst)

logis = LogisticRegression(max_iter=1000)
logis.fit(xtr,ytr)

ypr = logis.predict(xtst)

acc = accuracy_score(ytst,ypr)
print(acc)

joblib.dump(logis,'logistic.joblib')

