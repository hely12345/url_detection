from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score,precision_score,confusion_matrix, mean_absolute_error, mean_squared_error,roc_auc_score,confusion_matrix
from sklearn.model_selection import train_test_split,cross_val_score
import pandas as pd
from urllib.parse import urlsplit,urlparse
import joblib
data = pd.read_csv('ready_final_final.csv')
cols = ['Unnamed: 0','domain','type','tld','url','is_https','DomainAge','DomainEndPeriod']
X = data.drop(cols,axis=1)
y = data['type']
xtr, xtst, ytr, ytst = train_test_split(X,y,test_size=0.2,random_state=1)
rf = RandomForestClassifier(n_estimators=100,random_state=42)
rf.fit(xtr,ytr)
ypr = rf.predict(xtst)
y_prob = rf.predict_proba(xtst)
acc = accuracy_score(ytst,ypr)
roc = roc_auc_score(ytst, y_prob[:, 1])
print(acc)
print(roc)
print(confusion_matrix(ytst,ypr))
joblib.dump(rf,'random_forest.joblib')

print(rf.feature_importances_)
print(rf.score(xtst, ytst))
