#!/usr/bin/env python3
"""
Quick test script to verify Python environment
"""

def test_imports():
    """Test if all required packages can be imported"""
    try:
        import pandas as pd
        print("✅ pandas imported")
        
        import numpy as np
        print("✅ numpy imported")
        
        from sklearn.ensemble import RandomForestClassifier
        print("✅ scikit-learn imported")
        
        import joblib
        print("✅ joblib imported")
        
        import matplotlib.pyplot as plt
        print("✅ matplotlib imported")
        
        import seaborn as sns
        print("✅ seaborn imported")
        
        from imblearn.over_sampling import SMOTE
        print("✅ imbalanced-learn imported")
        
        from flask import Flask
        print("✅ flask imported")
        
        import requests
        print("✅ requests imported")
        
        from bs4 import BeautifulSoup
        print("✅ beautifulsoup4 imported")
        
        print("\n🎉 All packages imported successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_dataset():
    """Test if dataset can be loaded"""
    try:
        import pandas as pd
        df = pd.read_csv('../dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
        print(f"✅ Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        print(f"✅ Target distribution: {df['label'].value_counts().to_dict()}")
        return True
    except Exception as e:
        print(f"❌ Dataset error: {e}")
        return False

def main():
    print("Testing Python Environment for Phishing Detection System")
    print("=" * 60)
    
    # Test imports
    imports_ok = test_imports()
    
    if imports_ok:
        print("\n" + "=" * 60)
        # Test dataset
        dataset_ok = test_dataset()
        
        if dataset_ok:
            print("\n🚀 Environment is ready! You can now run:")
            print("   python train_model.py")
        else:
            print("\n Fix dataset path issues first")
    else:
        print("\n Install missing packages first:")
        print("   pip install pandas numpy scikit-learn matplotlib seaborn joblib imbalanced-learn flask flask-cors requests beautifulsoup4")

if __name__ == "__main__":
    main()