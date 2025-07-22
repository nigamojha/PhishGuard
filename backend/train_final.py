# train_final_model.py


import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import seaborn as sns
import matplotlib.pyplot as plt

# --- 1. Load Dataset ---
print("Loading original dataset...")
data = pd.read_csv("PhishingData.csv", index_col="id")

# --- 2. Augment Data with a MORE REALISTIC 'DomainAge' ---
print("Augmenting data with a more realistic 'DomainAge' feature...")
# Phishing sites: Mostly young, but with some older ones (e.g., compromised domains)
phishing_age = np.random.triangular(
    left=1, mode=30, right=1000, size=data[data["CLASS_LABEL"] == 1].shape[0]
).astype(int)
# Legitimate sites: Mostly old, but with some new ones (e.g., new businesses)
legit_age = np.random.triangular(
    left=90, mode=3650, right=8000, size=data[data["CLASS_LABEL"] == 0].shape[0]
).astype(int)

data.loc[data["CLASS_LABEL"] == 1, "DomainAge"] = phishing_age
data.loc[data["CLASS_LABEL"] == 0, "DomainAge"] = legit_age

# --- 3. Prepare Data for Training ---
X = data.drop(["CLASS_LABEL"], axis=1)
y = data["CLASS_LABEL"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print("Data prepared for training.")

# --- 4. Train the Final Model ---
print("Training the final model...")
final_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
final_model.fit(X_train, y_train)
print("Model training complete.")

# --- 5. Full Evaluation ---
print("\n" + "=" * 60)
print("          Final Model Evaluation Results")
print("=" * 60)
predictions = final_model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"Accuracy: {accuracy * 100:.2f}%\n")

# Detailed Classification Report
print("Classification Report:")
# target_names are 'Legitimate' (for class 0) and 'Phishing' (for class 1)
print(
    classification_report(y_test, predictions, target_names=["Legitimate", "Phishing"])
)

# Confusion Matrix
print("Confusion Matrix:")
cm = confusion_matrix(y_test, predictions)
print(cm)
print("\n(Matrix interpretation: [[True Neg, False Pos], [False Neg, True Pos]])\n")
# A visual plot of the confusion matrix
try:
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Legitimate", "Phishing"],
        yticklabels=["Legitimate", "Phishing"],
    )
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.savefig("confusion_matrix.png")
    print("✅ Confusion matrix plot saved to 'confusion_matrix.png'")
except ImportError:
    print(
        "NOTE: Seaborn and Matplotlib not found. Skipping plot. To install: pip install seaborn matplotlib"
    )

print("=" * 60)

# --- 6. Save the Final Model ---
print("\nSaving the final model files (phishing_model_final.pkl)...")
joblib.dump(final_model, "phishing_model_final.pkl")
model_columns = list(X.columns)
joblib.dump(model_columns, "model_columns_final.pkl")
print("✅ Final model and column list saved successfully!")


# --- 7. (NEW) Extract and Save Feature Importances ---
print("\nExtracting feature importances...")

# Get the feature importances from the trained model
importances = final_model.feature_importances_
# Create a pandas Series for easier handling, with feature names as the index
feature_importance_series = pd.Series(importances, index=X.columns)

# Get the top 10 most important features
top_10_features = feature_importance_series.nlargest(10)

print("Top 10 most important features:")
print(top_10_features)

# Save the top 10 features and their scores to a file
joblib.dump(top_10_features.to_dict(), "feature_importances.pkl")
print("✅ Feature importances saved to 'feature_importances.pkl'")

import json

# Save the top 10 features to a JSON file
top_10_features.to_json("feature_importances.json", orient="index")
print("✅ Feature importances saved to 'feature_importances.json'")
