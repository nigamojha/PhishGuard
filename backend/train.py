# train_model.py (Final Corrected Version)

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# --- 1. Load the dataset ---
print("Loading dataset...")
# The first column 'id' is just an index, so we can tell pandas to use it as such.
data = pd.read_csv("PhishingData.csv", index_col="id")

# --- 2. Prepare the data ---
# Use the correct column name 'CLASS_LABEL'
X = data.drop(["CLASS_LABEL"], axis=1)
y = data["CLASS_LABEL"]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print("Data prepared for training.")

# --- 3. Train the Random Forest model ---
print("Training Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("Model training complete.")

# --- 4. Evaluate the model ---
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("-" * 50)
print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")
print("-" * 50)


# --- 5. Save the trained model and the feature list ---
print("Saving the model as 'phishing_model.pkl'...")
joblib.dump(model, "phishing_model.pkl")

# We also need to save the exact column order for our API later
model_columns = list(X.columns)
joblib.dump(model_columns, "model_columns.pkl")

print("Model and column list saved successfully!")
