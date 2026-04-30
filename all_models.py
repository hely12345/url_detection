from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

from sklearn.ensemble import VotingClassifier
from sklearn.metrics import accuracy_score, classification_report

data = pd.read_csv('ready_final_final.csv')
cols = ['Unnamed: 0','domain','type','tld','url','is_https','DomainAge','DomainEndPeriod']
X = data.drop(cols,axis=1)
y = data['type'].map({'legitimate':0,'phishing':1})
xtr, xtst, ytr, ytst = train_test_split(X,y,test_size=0.2,random_state=1)


def make_robust_pipeline(model):
    return Pipeline([
        ('imputer', SimpleImputer(strategy='median')), # Fills NaNs with the column median
        ('classifier', model)
    ])

models = [
    # ('lr', make_robust_pipeline(LogisticRegression(max_iter=2000))),
    ('rf', make_robust_pipeline(RandomForestClassifier(n_estimators=100, random_state=1))),
    ('xgb', XGBClassifier(random_state=1)), # Handles NaNs natively
    ('lgbm', LGBMClassifier(random_state=1, verbose=-1)), # Handles NaNs natively
    # ('nb', make_robust_pipeline(MultinomialNB())),
    # ('dt', make_robust_pipeline(DecisionTreeClassifier(random_state=1)))
]


ensemble = VotingClassifier(estimators=models, voting='soft')
ensemble.fit(xtr, ytr)
ypr = ensemble.predict(xtst)

print(f"Combined Ensemble Accuracy: {accuracy_score(ytst, ypr):.4f}")
print("\nDetailed Report:")
print(classification_report(ytst, ypr))


for name, model in models:
    model.fit(xtr, ytr)
    score = accuracy_score(ytst, model.predict(xtst))
    print(f"{name} individual accuracy: {score:.4f}")
#  BERT / MobileBERT