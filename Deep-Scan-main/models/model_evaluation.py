import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
import joblib

# Try to import PhishingDetector, create dummy if not available
try:
    from train_model import PhishingDetector
except ImportError:
    class PhishingDetector:
        def __init__(self):
            self.model = None
            self.scaler = None
        def load_model(self, path):
            pass

class ModelEvaluator:
    def __init__(self, model_path='models/saved_models/'):
        self.detector = PhishingDetector()
        self.detector.load_model(model_path)
        
    def evaluate_model(self, test_data_path):
        """Comprehensive model evaluation"""
        # Load test data
        df = pd.read_csv(test_data_path)
        feature_cols = [col for col in df.columns if col not in ['FILENAME', 'URL', 'label']]
        
        X_test = df[feature_cols].fillna(df[feature_cols].median())
        y_test = df['label']
        
        # Scale features
        X_test_scaled = self.detector.scaler.transform(X_test)
        
        # Predictions
        y_pred = self.detector.model.predict(X_test_scaled)
        y_pred_proba = self.detector.model.predict_proba(X_test_scaled)
        
        # Print detailed metrics
        print("=== Detailed Model Evaluation ===")
        print(f"Test set size: {len(y_test)}")
        print(f"Accuracy: {(y_pred == y_test).mean():.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                  target_names=['Phishing', 'Legitimate']))
        
        # Confusion Matrix
        self.plot_confusion_matrix(y_test, y_pred)
        
        # ROC Curve
        self.plot_roc_curve(y_test, y_pred_proba[:, 1])
        
        # Precision-Recall Curve
        self.plot_precision_recall_curve(y_test, y_pred_proba[:, 1])
        
        # Threshold Analysis
        self.analyze_thresholds(y_test, y_pred_proba[:, 1])
        
        return y_test, y_pred, y_pred_proba
    
    def plot_confusion_matrix(self, y_true, y_pred):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Phishing', 'Legitimate'],
                   yticklabels=['Phishing', 'Legitimate'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig('models/confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_roc_curve(self, y_true, y_scores):
        """Plot ROC curve"""
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.3f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('models/roc_curve.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print(f"ROC AUC Score: {roc_auc:.4f}")
    
    def plot_precision_recall_curve(self, y_true, y_scores):
        """Plot Precision-Recall curve"""
        precision, recall, _ = precision_recall_curve(y_true, y_scores)
        avg_precision = average_precision_score(y_true, y_scores)
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, color='blue', lw=2,
                label=f'PR curve (AP = {avg_precision:.3f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend(loc="lower left")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('models/precision_recall_curve.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print(f"Average Precision Score: {avg_precision:.4f}")
    
    def analyze_thresholds(self, y_true, y_scores):
        """Analyze different probability thresholds"""
        thresholds = np.arange(0.1, 1.0, 0.1)
        results = []
        
        for threshold in thresholds:
            y_pred_thresh = (y_scores >= threshold).astype(int)
            
            # Calculate metrics
            tp = ((y_pred_thresh == 1) & (y_true == 1)).sum()
            fp = ((y_pred_thresh == 1) & (y_true == 0)).sum()
            tn = ((y_pred_thresh == 0) & (y_true == 0)).sum()
            fn = ((y_pred_thresh == 0) & (y_true == 1)).sum()
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = (tp + tn) / (tp + fp + tn + fn)
            
            results.append({
                'threshold': threshold,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'accuracy': accuracy
            })
        
        results_df = pd.DataFrame(results)
        
        # Plot threshold analysis
        plt.figure(figsize=(12, 8))
        plt.subplot(2, 2, 1)
        plt.plot(results_df['threshold'], results_df['precision'], 'o-', label='Precision')
        plt.xlabel('Threshold')
        plt.ylabel('Precision')
        plt.title('Precision vs Threshold')
        plt.grid(True, alpha=0.3)
        
        plt.subplot(2, 2, 2)
        plt.plot(results_df['threshold'], results_df['recall'], 'o-', label='Recall', color='orange')
        plt.xlabel('Threshold')
        plt.ylabel('Recall')
        plt.title('Recall vs Threshold')
        plt.grid(True, alpha=0.3)
        
        plt.subplot(2, 2, 3)
        plt.plot(results_df['threshold'], results_df['f1_score'], 'o-', label='F1-Score', color='green')
        plt.xlabel('Threshold')
        plt.ylabel('F1-Score')
        plt.title('F1-Score vs Threshold')
        plt.grid(True, alpha=0.3)
        
        plt.subplot(2, 2, 4)
        plt.plot(results_df['threshold'], results_df['accuracy'], 'o-', label='Accuracy', color='red')
        plt.xlabel('Threshold')
        plt.ylabel('Accuracy')
        plt.title('Accuracy vs Threshold')
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('models/threshold_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Find optimal threshold
        optimal_idx = results_df['f1_score'].idxmax()
        optimal_threshold = results_df.loc[optimal_idx, 'threshold']
        
        print(f"\nOptimal threshold (based on F1-score): {optimal_threshold:.1f}")
        print("Metrics at optimal threshold:")
        print(results_df.loc[optimal_idx])
        
        return results_df
    
    def test_sample_urls(self):
        """Test the model with sample URLs"""
        print("\n=== Testing Sample Predictions ===")
        
        # Note: This is a simplified example. In practice, you'd need to extract
        # all 47 features from the URL. For demonstration, we'll use random values
        # that represent typical feature patterns.
        
        sample_features = {
            'legitimate_example': np.random.rand(47) * 0.5 + 0.5,  # Higher values
            'phishing_example': np.random.rand(47) * 0.3           # Lower values
        }
        
        for name, features in sample_features.items():
            features_reshaped = features.reshape(1, -1)
            result = self.detector.predict(features_reshaped)
            
            print(f"\n{name}:")
            print(f"  Prediction: {result['prediction']}")
            print(f"  Confidence: {result['confidence']:.3f}")
            print(f"  Phishing probability: {result['probabilities']['phishing']:.3f}")
            print(f"  Legitimate probability: {result['probabilities']['legitimate']:.3f}")

def main():
    evaluator = ModelEvaluator()
    
    # Evaluate on test data (using same dataset for demo - in practice use separate test set)
    y_test, y_pred, y_pred_proba = evaluator.evaluate_model('dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
    
    # Test sample predictions
    evaluator.test_sample_urls()
    
    print("\n=== Evaluation Complete ===")
    print("All evaluation plots saved in models/ directory")

if __name__ == "__main__":
    main()