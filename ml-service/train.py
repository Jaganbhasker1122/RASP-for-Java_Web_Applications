import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import pickle
import os

def load_data():
    df = pd.read_csv('dataset.csv')
    X = df[['length', 'special_char_count', 'has_sql_keywords', 'has_script_tags', 'encoding_flag']]
    y = df['label']
    return X, y

def train_model():
    print("Loading dataset...")
    try:
        X, y = load_data()
    except Exception as e:
        print(f"Error loading data: {e}")
        return

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Logistic Regression Model...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    score = model.score(X_test, y_test)
    print(f"Model trained successfully. Test Accuracy: {score * 100:.2f}%")

    # Save the model
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("Model saved to model.pkl")

if __name__ == "__main__":
    train_model()
