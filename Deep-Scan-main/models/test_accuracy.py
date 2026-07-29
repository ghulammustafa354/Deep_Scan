import pandas as pd
import sys
import os
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import numpy as np

# Add backend directory to path - Multiple approaches for reliability
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Also add current directory and parent directory
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from predict import URLPredictor
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Python path: {sys.path}")
    print("Please run this script from the project root directory")
    sys.exit(1)

def test_model_accuracy():
    """Test the model accuracy on sample dataset"""
    
    # Load test data
    df = pd.read_csv('../dataset/sample_urls.csv')
    
    # Initialize predictor
    predictor = URLPredictor()
    
    predictions = []
    true_labels = []
    
    print("Testing URLs...")
    print("=" * 60)
    
    for idx, row in df.iterrows():
        url = row['url']
        true_label = row['label']
        
        # Get prediction
        result = predictor.predict_url(url)
        predicted_label = 1 if result['prediction'] == 'Legitimate' else 0
        
        predictions.append(predicted_label)
        true_labels.append(true_label)
        
        # Show individual results
        status = "PASS" if predicted_label == true_label else "FAIL"
        print(f"{status} {url[:50]:<50} | True: {'Legit' if true_label else 'Phish'} | Pred: {result['prediction']} ({result['confidence']:.3f})")
    
    # Calculate metrics
    accuracy = accuracy_score(true_labels, predictions)
    
    print("\n" + "=" * 60)
    print("RESULTS:")
    print(f"Accuracy: {accuracy:.3f} ({accuracy*100:.1f}%)")
    
    print("\nClassification Report:")
    print(classification_report(true_labels, predictions, target_names=['Phishing', 'Legitimate']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(true_labels, predictions)
    print(f"True Negatives (Phishing correctly identified): {cm[0,0]}")
    print(f"False Positives (Legitimate marked as Phishing): {cm[1,0]}")
    print(f"False Negatives (Phishing marked as Legitimate): {cm[0,1]}")
    print(f"True Positives (Legitimate correctly identified): {cm[1,1]}")
    
    return accuracy, predictions, true_labels

if __name__ == "__main__":
    test_model_accuracy()