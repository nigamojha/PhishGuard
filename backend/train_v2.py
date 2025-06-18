# train_model_v2.py

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import numpy as np

# --- 1. Load the original dataset ---
print("Loading original dataset...")
data = pd.read_csv('PhishingData.csv', index_col='id')

# --- 2. Augment Data with Simulated 'DomainAge' ---
# This is a crucial step for the dissertation. We are creating a new feature.
# We simulate it: phishing sites are young (e.g., < 180 days), legitimate sites are old.
print("Augmenting data with simulated 'DomainAge' feature...")
# Generate random ages: low values for phishing, high values for legitimate
phishing_age = np.random.randint(1, 180, size=data[data['CLASS_LABEL'] == 1].shape[0])
legit_age = np.random.randint(365, 7300, size=data[data['CLASS_LABEL'] == 0].shape[0])

# Add the new column to the dataframe
data.loc[data['CLASS_LABEL'] == 1, 'DomainAge'] = phishing_age
data.loc[data['CLASS_LABEL'] == 0, 'DomainAge'] = legit_age

print("Data augmentation complete.")

# --- 3. Prepare the Augmented Data ---
X = data.drop(['CLASS_LABEL'], axis=1)
y = data['CLASS_LABEL']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Augmented data prepared for training.")

# --- 4. Train the new v2 model ---
print("Training new v2 model...")
model_v2 = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model_v2.fit(X_train, y_train)
print("Model training complete.")

# --- 5. Evaluate the v2 model ---
predictions = model_v2.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("-" * 50)
print(f"✅ New v2 Model Accuracy: {accuracy * 100:.2f}%")
print("-" * 50)

# --- 6. Save the new v2 model and columns ---
print("Saving the new v2 model and columns...")
joblib.dump(model_v2, 'phishing_model_v2.pkl')

model_columns_v2 = list(X.columns)
joblib.dump(model_columns_v2, 'model_columns_v2.pkl')

print("v2 Model and column list saved successfully!")