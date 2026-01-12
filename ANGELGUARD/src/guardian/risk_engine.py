from sklearn.ensemble import RandomForestClassifier
import numpy as np
import os
import joblib
from src.utils.logger import guardian_logger

class RiskEngine:
    def __init__(self, model_path="data/models/risk_model.pkl"):
        self.model_path = model_path
        self.model = None
        self._load_or_create_model()

    def _load_or_create_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                guardian_logger.logger.error(f"Failed to load model: {e}")
        
        if self.model is None:
            guardian_logger.logger.warning("No model found. initializing dummy model.")
            # Simple dummy model for MVP/Demo
            self.model = RandomForestClassifier(n_estimators=10)
            # Mock training to avoid errors
            X_dummy = np.array([[0, 0], [10, 10]]) # [entropy, num_imports]
            y_dummy = np.array([0, 1]) # 0=Safe, 1=Suspicious
            self.model.fit(X_dummy, y_dummy)

    def assess_risk(self, analysis_results):
        """
        Returns a score between 0 (Safe) and 100 (Cryptic/Malicious)
        """
        # Feature Extraction (Simplified for MVP)
        entropy = analysis_results.get("entropy", 0)
        num_imports = len(analysis_results.get("imports", []))
        
        # Heuristic Checks (Override ML for obvious cases in MVP)
        score = 0
        reasons = []

        if entropy > 7.0:
            score += 40
            reasons.append("High Entropy (Packed/Encrypted)")
        
        if num_imports < 3 and analysis_results.get("is_pe"):
            score += 30
            reasons.append("Few Imports (Suspicious)")

        # ML Prediction (Mock)
        try:
            ml_prob = self.model.predict_proba([[entropy, num_imports]])[0][1] # Probability of class 1
            ml_score = ml_prob * 30 # Max 30 points from ML
            score += ml_score
        except:
            pass
        
        # Cap score
        score = min(100, score)
        
        return {
            "score": round(score, 2),
            "level": "Safe" if score < 50 else "Suspicious",
            "reasons": reasons
        }
