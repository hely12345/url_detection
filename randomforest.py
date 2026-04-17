from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score,precision_score,confusion_matrix, mean_absolute_error, mean_squared_error
from sklearn.model_selection import train_test_split,cross_val_score
import pandas as pd
from urllib.parse import urlsplit,urlparse
import joblib
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

data = pd.read_csv('ready_final_final.csv')
# print(data.info())
cols = ['Unnamed: 0','domain','type','tld','url','is_https','DomainAge','DomainEndPeriod']

X = data.drop(cols,axis=1)

# le = LabelEncoder()
y = data['type']

xtr, xtst, ytr, ytst = train_test_split(X,y,test_size=0.2,random_state=1)

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

# xg = XGBClassifier(
#     n_estimators = 500,
#     learning_rate = 0.01
# )

rf.fit(xtr,ytr)
# xg.fit(xtr,ytr)

ypr = rf.predict(xtst)
# ypr = xg.predict(xtst)

acc = accuracy_score(ytst,ypr)
print(acc)

joblib.dump(rf,'random_forest.joblib')

# importance = pd.Series(rf.feature_importances_, index=X.columns)
# print(importance.sort_values(ascending=False).head(15))
 
# scores = cross_val_score(rf, X, y, cv=5)
# print("Mean CV accuracy:", scores.mean())