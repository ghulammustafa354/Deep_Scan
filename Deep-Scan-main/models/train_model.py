import pandas as pd
import numpy as np
import sys
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import warnings
import time

warnings.filterwarnings('ignore')

# Add backend folder to path to import predict
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
from predict import URLFeatureExtractor

class PhishingDetectorTrainer:
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.scaler_url = StandardScaler()
        self.scaler_full = StandardScaler()
        
        self.feature_names_url = [
            'URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex', 
            'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 'TLDLength', 
            'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
            'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
            'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
            'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS'
        ]
        
        self.web_feature_names = [
            'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore', 
            'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive', 
            'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup', 
            'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton', 
            'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto', 
            'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 
            'NoOfEmptyRef', 'NoOfExternalRef'
        ]
        
        self.feature_names_full = self.feature_names_url + self.web_feature_names

    def load_and_align_dataset(self, csv_path):
        print("Loading original PhiUSIIL dataset...")
        df = pd.read_csv(csv_path)
        print(f"Loaded {len(df)} rows.")
        
        # 1. Extract URL-only features using our extractor for ALL rows
        print("Aligning URL features using our URLFeatureExtractor (running via pandas)...")
        start_time = time.time()
        
        # Run extractor on each URL
        extracted_list = []
        for idx, url in enumerate(df['URL']):
            if idx > 0 and idx % 50000 == 0:
                print(f"  Processed {idx} URLs...")
            extracted_list.append(self.feature_extractor.extract_url_features(url))
            
        extracted_df = pd.DataFrame(extracted_list)
        print(f"Alignment complete in {time.time() - start_time:.2f} seconds.")
        
        # Fill any missing values in our extracted features
        extracted_df = extracted_df[self.feature_names_url].fillna(extracted_df[self.feature_names_url].median())
        
        # 2. Extract web features from the original CSV
        print("Extracting web features from dataset CSV...")
        web_df = df[self.web_feature_names].copy()
        web_df = web_df.fillna(web_df.median())
        
        # Combine extracted URL features with web features
        X_full = pd.concat([extracted_df, web_df], axis=1)
        X_url = extracted_df
        y = df['label']
        
        return X_url, X_full, y

    def train_models(self, X_url, X_full, y):
        # 1. Split data (same split using random_state for consistency)
        X_train_url, X_test_url, y_train, y_test = train_test_split(
            X_url, y, test_size=0.2, random_state=42, stratify=y
        )
        X_train_full, X_test_full, _, _ = train_test_split(
            X_full, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_url_scaled = self.scaler_url.fit_transform(X_train_url)
        X_test_url_scaled = self.scaler_url.transform(X_test_url)
        
        X_train_full_scaled = self.scaler_full.fit_transform(X_train_full)
        X_test_full_scaled = self.scaler_full.transform(X_test_full)
        
        # Train Random Forest classifiers
        rf_params = {
            'n_estimators': 30,
            'max_depth': 8,
            'min_samples_split': 50,
            'min_samples_leaf': 20,
            'max_features': 0.7,
            'random_state': 42,
            'n_jobs': -1
        }
        
        print("\n--- Training URL-only Model (22 features) ---")
        self.model_url = RandomForestClassifier(**rf_params)
        self.model_url.fit(X_train_url_scaled, y_train)
        y_pred_url = self.model_url.predict(X_test_url_scaled)
        print(f"URL-only Model Accuracy: {accuracy_score(y_test, y_pred_url):.4f}")
        print(classification_report(y_test, y_pred_url))
        
        print("\n--- Training Full Model (50 features) ---")
        self.model_full = RandomForestClassifier(**rf_params)
        self.model_full.fit(X_train_full_scaled, y_train)
        y_pred_full = self.model_full.predict(X_test_full_scaled)
        print(f"Full Model Accuracy: {accuracy_score(y_test, y_pred_full):.4f}")
        print(classification_report(y_test, y_pred_full))
        
        # Cross-validation
        cv_url = cross_val_score(self.model_url, X_train_url_scaled, y_train, cv=5, scoring='accuracy')
        cv_full = cross_val_score(self.model_full, X_train_full_scaled, y_train, cv=5, scoring='accuracy')
        print(f"Mean CV Accuracy (URL-only): {cv_url.mean():.4f}")
        print(f"Mean CV Accuracy (Full): {cv_full.mean():.4f}")

    def save_models(self, model_path='models/saved_models/'):
        os.makedirs(model_path, exist_ok=True)
        
        # Save URL model details
        joblib.dump(self.model_url, f'{model_path}phishing_detector_url.pkl')
        joblib.dump(self.scaler_url, f'{model_path}scaler_url.pkl')
        joblib.dump(self.feature_names_url, f'{model_path}feature_names_url.pkl')
        
        # Save Full model details
        joblib.dump(self.model_full, f'{model_path}phishing_detector_full.pkl')
        joblib.dump(self.scaler_full, f'{model_path}scaler_full.pkl')
        joblib.dump(self.feature_names_full, f'{model_path}feature_names_full.pkl')
        
        print(f"All aligned models saved successfully to {model_path}")

def main():
    trainer = PhishingDetectorTrainer()
    X_url, X_full, y = trainer.load_and_align_dataset('dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
    trainer.train_models(X_url, X_full, y)
    trainer.save_models('models/saved_models/')
    print("\n=== Model Training and Alignment Complete ===")

if __name__ == "__main__":
    main()