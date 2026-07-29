"""
Retrain using features extracted by our own URLFeatureExtractor on dataset URLs.
This eliminates the training/runtime mismatch completely.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
import joblib
import warnings
warnings.filterwarnings('ignore')

from predict import URLFeatureExtractor

DATASET   = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'PhiUSIIL_Phishing_URL_Dataset.csv')
SAVE_PATH = os.path.join(os.path.dirname(__file__), 'saved_models')

def extract_all(df, sample_size=50000):
    """Run extractor on dataset URLs and return feature matrix + labels."""
    extractor = URLFeatureExtractor()

    # Sample evenly from both classes to keep balance
    legit   = df[df['label'] == 1].sample(sample_size // 2, random_state=42)
    phish   = df[df['label'] == 0].sample(sample_size // 2, random_state=42)
    sampled = pd.concat([legit, phish]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Extracting features from {len(sampled)} URLs using our extractor...")
    rows, labels = [], []
    for i, row in sampled.iterrows():
        try:
            feats = extractor.extract_features(row['URL'])
            rows.append(feats)
            labels.append(row['label'])
        except Exception:
            continue
        if len(rows) % 5000 == 0:
            print(f"  {len(rows)}/{len(sampled)} done...")

    print(f"Extraction complete: {len(rows)} URLs processed")
    return np.array(rows), np.array(labels)


def train(X, y):
    scaler = StandardScaler()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
                                                         random_state=42, stratify=y)
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    smote = SMOTE(random_state=42)
    X_train_sc, y_train = smote.fit_resample(X_train_sc, y_train)

    model = RandomForestClassifier(
        n_estimators=100, max_depth=12,
        min_samples_split=20, min_samples_leaf=10,
        max_features='sqrt', random_state=42, n_jobs=-1
    )
    model.fit(X_train_sc, y_train)

    y_pred = model.predict(X_test_sc)
    print("\n=== Real Model Performance ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred,
                                 target_names=['Phishing', 'Legitimate']))
    return model, scaler


if __name__ == '__main__':
    df = pd.read_csv(DATASET)
    print(f"Dataset loaded: {df.shape}, labels: {df['label'].value_counts().to_dict()}")

    X, y = extract_all(df, sample_size=50000)

    feature_names = [
        'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
        'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
        'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
        'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
        'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS'
    ]

    model, scaler = train(X, y)

    os.makedirs(SAVE_PATH, exist_ok=True)
    joblib.dump(model,        os.path.join(SAVE_PATH, 'phishing_detector.pkl'))
    joblib.dump(scaler,       os.path.join(SAVE_PATH, 'scaler.pkl'))
    joblib.dump(feature_names, os.path.join(SAVE_PATH, 'feature_names.pkl'))
    print(f"\nModel saved to {SAVE_PATH}")
    print("Done! Model now trained on extractor's own feature computation.")
