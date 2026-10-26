"""Module suy luận thời gian thực cho dữ liệu Streaming CDC."""
import os
import joblib
import pandas as pd

class StreamingInference:
    def __init__(self, model_path="models/multiclass_rf_v1.joblib"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Không tìm thấy mô hình: {model_path}")
        
        loaded = joblib.load(model_path)
        if isinstance(loaded, dict):
            self.model = loaded.get("pipeline", loaded.get("model"))
            self.features = loaded.get("features", [])
            self.classes = loaded.get("classes", [])
            if not self.features and hasattr(self.model, "feature_names_in_"):
                self.features = list(self.model.feature_names_in_)
        else:
            self.model = loaded
            if hasattr(self.model, "feature_names_in_"):
                self.features = list(self.model.feature_names_in_)
            else:
                self.features = []

        if not self.features:
            raise AttributeError("Mô hình không lưu trữ thông tin features hoặc feature_names_in_.")

    def predict(self, df: pd.DataFrame):
        if df.empty:
            return []
        
        # Đảm bảo Dataframe có đủ các cột đặc trưng mô hình cần (điền 0 nếu thiếu)
        X = pd.DataFrame(index=df.index)
        for col in self.features:
            X[col] = df[col] if col in df.columns else 0
            
        # Trả về mảng nhãn dự đoán (ví dụ: 'Benign', 'DDoS', 'PortScan'...)
        return self.model.predict(X)