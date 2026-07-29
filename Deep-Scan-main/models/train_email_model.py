import os
import sys
import pandas as pd
import numpy as np
import pickle
import re
import email
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

# Add NLTK imports
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

print("Initializing training script dependencies...")

# Download NLTK datasets safely if missing
for dataset in ['punkt', 'stopwords', 'punkt_tab']:
    try:
        nltk.data.find(f'tokenizers/{dataset}' if 'punkt' in dataset else f'corpora/{dataset}')
    except Exception:
        try:
            nltk.download(dataset, quiet=True)
        except Exception:
            pass

# Set path locations
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
CEAS_PATH = os.path.join(DATASET_DIR, 'CEAS_08.csv')
ENRON_PATH = os.path.join(DATASET_DIR, 'emails.csv')
MODEL_OUT_DIR = os.path.join(BASE_DIR, 'models', 'saved_models')
MODEL_OUT_PATH = os.path.join(MODEL_OUT_DIR, 'email_phishing_model.pkl')

os.makedirs(MODEL_OUT_DIR, exist_ok=True)

# ----------------------------------------------------------------------------
# 1. PARSING THE LARGE ENRON DATASET
# ----------------------------------------------------------------------------
def parse_raw_enron_message(raw_msg):
    """
    Parses subject and plain text body from raw Enron email RFC-822 message format.
    """
    try:
        msg = email.message_from_string(str(raw_msg))
        subject = msg.get('Subject', '')
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
                
        return subject, body.strip()
    except Exception:
        return "", ""

def load_enron_ham_dataset(filepath, max_instances=15000):
    """
    Loads a sample of clean corporate ham emails from the raw 1.42 GB Enron emails.csv file.
    Uses chunking to keep memory footprints low.
    """
    print(f"Loading Enron ham emails from: {filepath}...")
    ham_data = []
    
    # We read in chunks to prevent memory overflows with the 1.42 GB file
    chunksize = 20000
    try:
        for chunk in pd.read_csv(filepath, chunksize=chunksize):
            for _, row in chunk.iterrows():
                raw_message = row.get('message', '')
                if not raw_message:
                    continue
                
                subject, body = parse_raw_enron_message(raw_message)
                # Filter out extremely short or empty body emails
                if len(body) > 30:
                    ham_data.append({
                        'subject': subject,
                        'body': body,
                        'label': 0  # 0 represents Legitimate
                    })
                    if len(ham_data) >= max_instances:
                        break
            if len(ham_data) >= max_instances:
                break
        print(f"[SUCCESS] Loaded {len(ham_data)} legitimate emails from Enron dataset.")
    except Exception as e:
        print(f"[WARNING] Could not parse Enron emails: {e}. Falling back to CEAS-only ham.")
        
    return pd.DataFrame(ham_data)

# ----------------------------------------------------------------------------
# 2. LOADING CEAS_08 DATASET
# ----------------------------------------------------------------------------
def load_ceas_dataset(filepath):
    """
    Loads the pre-structured CEAS_08 email dataset.
    """
    print(f"Loading CEAS_08 email dataset from: {filepath}...")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"CEAS_08.csv not found at: {filepath}")
        
    df = pd.read_csv(filepath)
    df = df[['subject', 'body', 'label']].dropna()
    df['label'] = df['label'].astype(int)
    print(f"[SUCCESS] Loaded {len(df)} emails from CEAS_08 (Phishing: {sum(df['label'] == 1)}, Ham: {sum(df['label'] == 0)}).")
    return df

# ----------------------------------------------------------------------------
# 3. TEXT PREPROCESSING
# ----------------------------------------------------------------------------
stemmer = PorterStemmer()
try:
    stop_words = set(stopwords.words('english'))
except Exception:
    stop_words = set()

def preprocess_email_text(subject, body):
    """
    Normalizes subject and body text, removes punctuation, handles stemming and stopwords.
    """
    text = f"{subject} {body}"
    # Lowercase & remove non-alphabet characters
    text = re.sub(r'[^a-zA-Z\s]', '', text.lower())
    # Split into words
    words = text.split()
    # Filter stopwords and stem remaining words
    filtered_words = [stemmer.stem(w) for w in words if w not in stop_words]
    return " ".join(filtered_words)

# ----------------------------------------------------------------------------
# MAIN EXECUTION ROUTINE
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    # Load data
    ceas_df = load_ceas_dataset(CEAS_PATH)
    enron_df = load_enron_ham_dataset(ENRON_PATH, max_instances=15000)
    
    # Merge datasets
    print("Merging and balancing corpora...")
    all_dfs = [ceas_df]
    if not enron_df.empty:
        all_dfs.append(enron_df)
        
    combined_df = pd.concat(all_dfs, ignore_index=True)
    print(f"Total instances compiled: {len(combined_df)}")
    
    # Preprocess text
    print("Normalizing and tokenizing email corpus (this may take a few minutes)...")
    combined_df['processed_text'] = combined_df.apply(
        lambda r: preprocess_email_text(r['subject'], r['body']), axis=1
    )
    
    # Filter out empty texts
    combined_df = combined_df[combined_df['processed_text'].str.strip() != ""]
    
    # Split dataset
    X = combined_df['processed_text']
    y = combined_df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Training size: {len(X_train)}, Testing size: {len(X_test)}")
    
    # Vectorization
    print("Vectorizing text using TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)
    
    # Model Classifier
    print("Training Logistic Regression classifier...")
    classifier = LogisticRegression(max_iter=1000, C=1.0, class_weight='balanced')
    classifier.fit(X_train_vectorized, y_train)
    
    # Evaluation
    predictions = classifier.predict(X_test_vectorized)
    print("\n" + "="*50)
    print("MODEL PERFORMANCE METRICS")
    print("="*50)
    print(f"Validation Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=['Legitimate', 'Phishing']))
    print("="*50 + "\n")
    
    # Save the pipeline
    print(f"Saving trained classifier pipeline to: {MODEL_OUT_PATH}")
    model_data = {
        'vectorizer': vectorizer,
        'model': classifier
    }
    with open(MODEL_OUT_PATH, 'wb') as f:
        pickle.dump(model_data, f)
        
    print("[SUCCESS] Email phishing detection model updated successfully!")
