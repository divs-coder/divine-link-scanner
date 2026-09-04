from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

print("Loading phishing dataset...")

dataset = fetch_ucirepo(id=967)

X = dataset.data.features
y = dataset.data.targets.squeeze()

# Remove columns that aren't useful for this first model
drop_columns = ["FILENAME", "URL", "Domain", "TLD"]

X = X.drop(
    columns=[c for c in drop_columns if c in X.columns],
    errors="ignore"
)

print("Dataset loaded.")
print("Rows:", len(X))
print("Features:", len(X.columns))

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("\nModel evaluation:")
predictions = model.predict(X_test)

print(
    classification_report(
        y_test,
        predictions
    )
)

joblib.dump(
    {
        "model": model,
        "features": list(X.columns)
    },
    "phishing_model.joblib"
)

print("\nModel saved as phishing_model.joblib")
