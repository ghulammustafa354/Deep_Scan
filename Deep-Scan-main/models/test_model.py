import pandas as pd
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from predict import URLPredictor
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

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
        true_str = 'Legit' if true_label else 'Phish'
        pred_str = result['prediction']
        conf = result['confidence']
        
        print(f"{status} {url[:45]:<45} | True: {true_str} | Pred: {pred_str} ({conf:.3f})")
    
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
    
    return accuracy

if __name__ == "__main__":
    test_model_accuracy()