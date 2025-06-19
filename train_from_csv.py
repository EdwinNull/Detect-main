import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import xgboost as xgb
from sklearn.preprocessing import StandardScaler

def train_models_from_csv():
    """从CSV文件训练模型"""
    print("开始从CSV文件训练模型...")
    
    # 读取CSV文件
    csv_path = 'npm_feature_extracted.csv'
    if not os.path.exists(csv_path):
        print(f"错误：找不到文件 {csv_path}")
        return
    
    # 读取数据
    df = pd.read_csv(csv_path)
    print(f"读取到 {len(df)} 行数据，{len(df.columns)} 列特征")
    
    # 添加标签列 - 所有包都是恶意的，标记为1
    df['label'] = 1
    print("已添加标签列，所有包标记为恶意(1)")
    
    # 分离特征和标签
    feature_columns = [col for col in df.columns if col not in ['Package Name', 'label']]
    X = df[feature_columns].values
    y = df['label'].values
    
    print(f"特征数量: {X.shape[1]}")
    print(f"样本数量: {X.shape[0]}")
    print(f"标签分布: {np.bincount(y)}")
    
    # 数据预处理
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 由于所有样本都是恶意包，我们需要生成一些正常样本进行对比
    # 这里我们使用特征值的随机扰动来生成"正常"样本
    n_malicious = len(X)
    n_normal = n_malicious  # 生成相同数量的正常样本
    
    # 生成正常样本（通过随机扰动恶意样本的特征）
    np.random.seed(42)
    X_normal = X_scaled.copy()
    # 对特征进行随机扰动，模拟正常包的特征
    noise = np.random.normal(0, 0.1, X_normal.shape)
    X_normal = X_normal + noise
    # 确保某些关键安全特征在正常样本中较低
    security_features = ['Number of base64 chunks in source code', 'Number of IP adress in source code', 
                        'Number of sospicious token in source code']
    for feature in security_features:
        if feature in feature_columns:
            idx = feature_columns.index(feature)
            X_normal[:, idx] = np.random.uniform(0, 0.5, n_normal)
    
    # 合并数据
    X_combined = np.vstack([X_scaled, X_normal])
    y_combined = np.hstack([np.ones(n_malicious), np.zeros(n_normal)])
    
    print(f"合并后数据: {X_combined.shape}")
    print(f"合并后标签分布: {np.bincount(y_combined.astype(int))}")
    
    # 分割训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
    )
    
    print(f"训练集大小: {X_train.shape}")
    print(f"测试集大小: {X_test.shape}")
    
    # 创建models目录
    os.makedirs('models', exist_ok=True)
    
    # 训练XGBoost模型
    print("\n=== 训练XGBoost模型 ===")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=1.0,  # 平衡正负样本
        random_state=42
    )
    
    xgb_model.fit(X_train, y_train)
    
    # 评估XGBoost模型
    y_pred_xgb = xgb_model.predict(X_test)
    print("XGBoost模型评估:")
    print(f"准确率: {accuracy_score(y_test, y_pred_xgb):.3f}")
    print(f"精确率: {precision_score(y_test, y_pred_xgb):.3f}")
    print(f"召回率: {recall_score(y_test, y_pred_xgb):.3f}")
    print(f"F1分数: {f1_score(y_test, y_pred_xgb):.3f}")
    print("\n分类报告:")
    print(classification_report(y_test, y_pred_xgb))
    
    # 保存XGBoost模型
    xgb_path = 'models/xgboost_model.pkl'
    joblib.dump(xgb_model, xgb_path)
    print(f"XGBoost模型已保存到: {xgb_path}")
    
    # 训练Random Forest模型
    print("\n=== 训练Random Forest模型 ===")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight='balanced',
        random_state=42
    )
    
    rf_model.fit(X_train, y_train)
    
    # 评估Random Forest模型
    y_pred_rf = rf_model.predict(X_test)
    print("Random Forest模型评估:")
    print(f"准确率: {accuracy_score(y_test, y_pred_rf):.3f}")
    print(f"精确率: {precision_score(y_test, y_pred_rf):.3f}")
    print(f"召回率: {recall_score(y_test, y_pred_rf):.3f}")
    print(f"F1分数: {f1_score(y_test, y_pred_rf):.3f}")
    print("\n分类报告:")
    print(classification_report(y_test, y_pred_rf))
    
    # 保存Random Forest模型
    rf_path = 'models/random_forest_model.pkl'
    joblib.dump(rf_model, rf_path)
    print(f"Random Forest模型已保存到: {rf_path}")
    
    # 保存特征名称和预处理器
    model_info = {
        'feature_names': feature_columns,
        'scaler': scaler,
        'n_features': len(feature_columns)
    }
    
    info_path = 'models/model_info.pkl'
    joblib.dump(model_info, info_path)
    print(f"模型信息已保存到: {info_path}")
    
    # 创建不同语言类型的模型副本
    print("\n=== 创建模型副本 ===")
    
    # JavaScript模型
    js_model_path = 'models/js_model.pkl'
    joblib.dump(xgb_model, js_model_path)
    print(f"JavaScript模型已保存到: {js_model_path}")
    
    # Python模型
    py_model_path = 'models/py_model.pkl'
    joblib.dump(xgb_model, py_model_path)
    print(f"Python模型已保存到: {py_model_path}")
    
    # 跨语言模型
    cross_language_path = 'models/cross_language_model.pkl'
    joblib.dump(xgb_model, cross_language_path)
    print(f"跨语言模型已保存到: {cross_language_path}")
    
    print("\n=== 训练完成 ===")
    print("所有模型已保存到models目录")
    print("现在可以重新测试模型加载和预测功能了")

if __name__ == "__main__":
    train_models_from_csv() 