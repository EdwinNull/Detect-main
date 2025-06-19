import sqlite3
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier

class SecurityClassifier:
    def __init__(self, model_type='xgboost'):
        self.model_type = model_type
        self.model = None
        self.is_trained = False
        # 强制使用models目录下的模型文件
        self.model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'models', f'{model_type}_model.pkl')
        self.feature_names = []
        self.feature_groups = {}
        self._initialize_model()

    def _initialize_model(self):
        """初始化模型"""
        print(f"正在初始化{self.model_type}模型...")
        print(f"当前工作目录: {os.getcwd()}")
        print(f"模型加载路径: {self.model_path}")
        if self.model_type in ['js_model', 'py_model', 'cross_language', 'xgboost']:
            if os.path.exists(self.model_path):
                try:
                    self.model = joblib.load(self.model_path)
                    self.is_trained = True
                    print(f"成功加载{self.model_type}模型: {self.model_path}")
                    print(f"[DEBUG] 加载的模型对象: {self.model}")
                    return
                except Exception as e:
                    print(f"加载模型失败: {str(e)}")
            else:
                print(f"模型文件不存在: {self.model_path}")
            print(f"无法找到{self.model_type}模型文件，使用默认XGBoost模型")
            self.model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                scale_pos_weight=2.0,
                random_state=42
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=8,
                class_weight='balanced',
                random_state=42
            )

def predict(self, features):
    """预测包的风险等级"""
    if not self.is_trained:
        if self.model_type in ['js_model', 'py_model', 'cross_language']:
            print(f"错误: {self.model_type}模型未加载")
            return None
        print("开始训练模型...")
        self._train_model()
    try:
        # 提取特征
        feature_vector = []
        expected_features = 140  # 统一使用140个特征
        if len(self.feature_names) > expected_features:
            print(f"警告：当前特征数({len(self.feature_names)})超过预期({expected_features})，将截断多余特征")
            feature_names = self.feature_names[:expected_features]
        else:
            feature_names = self.feature_names
        for feature in feature_names:
            value = features.get(feature, 0)
            try:
                if isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                elif isinstance(value, bool):
                    feature_vector.append(1.0 if value else 0.0)
                elif isinstance(value, str):
                    if value.lower() in ['true', 'yes', 'on', 'enabled']:
                        feature_vector.append(1.0)
                    elif value.lower() in ['false', 'no', 'off', 'disabled']:
                        feature_vector.append(0.0)
                    else:
                        try:
                            float_value = float(value)
                            feature_vector.append(float_value)
                        except ValueError:
                            feature_vector.append(min(float(len(value)) / 1000.0, 1.0))
                elif isinstance(value, (dict, list, tuple, set)):
                    feature_vector.append(min(float(len(value)) / 100.0, 1.0))
                else:
                    feature_vector.append(0.0)
            except (ValueError, TypeError):
                print(f"警告：特征 {feature} 的值 {value} 无法转换为数值，使用默认值0.0")
                feature_vector.append(0.0)
        if len(feature_vector) < expected_features:
            print(f"警告：特征数量不足({len(feature_vector)}/{expected_features})，补充缺失特征")
            feature_vector.extend([0.0] * (expected_features - len(feature_vector)))
        print(f"特征向量大小: {len(feature_vector)}")
        feature_array = np.array(feature_vector).reshape(1, -1)
        prediction = self.model.predict(feature_array)[0]
            proba = self.model.predict_proba(feature_array)[0][1]  # 1为恶意概率
            risk_score = float(proba)
            # 风险等级判定
            if risk_score >= 0.7:
                risk_level = 'high'
            elif risk_score >= 0.4:
                risk_level = 'medium'
            elif risk_score >= 0.2:
                risk_level = 'low'
            else:
                risk_level = 'safe'
            result = {
            'prediction': int(prediction),
                'confidence': float(proba),
                'risk_score': risk_score,
                'risk_level': risk_level,
            'feature_importance': self._get_feature_importance(features)
        }
            if result['feature_importance'] is None:
                result['feature_importance'] = {}
            return result
    except Exception as e:
        print(f"预测错误: {str(e)}")
            return {
                'prediction': 0,
                'confidence': 0.5,
                'risk_score': 0.0,
                'risk_level': 'unknown',
                'feature_importance': {}
            }

def _train_model(self):
    """训练模型"""
    print("开始训练模型...")
    # 从数据库加载训练数据                                                         
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 获取所有已标记的扫描记录
    cursor.execute('''
        SELECT f.feature_data, s.risk_level
        FROM features f
        JOIN scan_records s ON f.scan_id = s.id
        WHERE s.risk_level IS NOT NULL
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    if not data:
        print("没有足够的训练数据，使用基于规则的初始化数据")
        self._train_with_rule_based_data()
        return
    
    # 准备训练数据
    X = []
    y = []
    for features, risk_level in data:
        try:
            feature_dict = json.loads(features)
            # 确保特征向量的长度正确
            feature_vector = []
            
            # 按特征名称顺序处理特征
            for feature in self.feature_names:
                value = feature_dict.get(feature, 0)
                # 确保特征值为数值类型
                try:
                    if isinstance(value, (int, float)):
                        feature_vector.append(float(value))
                    elif isinstance(value, bool):
                        feature_vector.append(1.0 if value else 0.0)
                    elif isinstance(value, str):
                        if value.lower() in ['true', 'yes', 'on', 'enabled']:
                            feature_vector.append(1.0)
                        elif value.lower() in ['false', 'no', 'off', 'disabled']:
                            feature_vector.append(0.0)
                        else:
                            # 对字符串特征进行更好的数值转换
                            try:
                                float_value = float(value)
                                feature_vector.append(float_value)
                            except ValueError:
                                # 如果无法转换为数值，使用字符串长度的归一化值
                                feature_vector.append(min(float(len(value)) / 1000.0, 1.0))
                    elif isinstance(value, (dict, list, tuple, set)):
                        # 对集合类型特征进行更好的数值转换
                        feature_vector.append(min(float(len(value)) / 100.0, 1.0))
                    else:
                        feature_vector.append(0.0)
                except (ValueError, TypeError):
                    print(f"警告：特征 {feature} 的值 {value} 无法转换为数值，使用默认值0.0")
                    feature_vector.append(0.0)
            
            # 确保特征向量长度正确
            if len(feature_vector) == len(self.feature_names):
                X.append(feature_vector)
                y.append(1 if risk_level == 'high' else 0)
            else:
                print(f"警告：特征向量长度不正确 ({len(feature_vector)} != {len(self.feature_names)})，跳过此样本")
        except Exception as e:
            print(f"处理训练数据时出错: {e}")
            continue
    
    if len(X) < 10:
        print("训练数据不足，使用基于规则的初始化数据")
        self._train_with_rule_based_data()
        return
    
    X = np.array(X)
    y = np.array(y)
    
    # 分割训练集和验证集
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 训练模型
    self.model.fit(X_train, y_train)
    
    # 评估模型
    y_pred = self.model.predict(X_val)
    accuracy = accuracy_score(y_val, y_pred)
    precision = precision_score(y_val, y_pred)
    recall = recall_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred)
    
    print(f"模型评估结果:")
    print(f"准确率: {accuracy:.3f}")
    print(f"精确率: {precision:.3f}")
    print(f"召回率: {recall:.3f}")
    print(f"F1分数: {f1:.3f}")
    
    # 保存模型
    os.makedirs('models', exist_ok=True)
    if self.model_type == 'xgboost':
        self.model.save_model(self.model_path)
    else:
        joblib.dump(self.model, self.model_path)
    
    self.is_trained = True
    print("模型训练完成并保存") 

        # 特征权重
        self.feature_weights = {
            'basic_file': 0.10,
            'project_structure': 0.15,
            'code_analysis': 0.20,
            'dependency_analysis': 0.15,
            'file_content': 0.15,
            'security': 0.25  # 增加安全特征的权重
        }
        
        # 风险阈值
        self.risk_thresholds = {
            'high': 0.6,    # 降低高风险阈值
            'medium': 0.4,  # 降低中等风险阈值
            'low': 0.2      # 降低低风险阈值
        } 

    def _calculate_risk_score(self, features):
        """计算风险分数"""
        score = 0.0
        
        # 计算每个特征组的得分
        for group, weight in self.feature_weights.items():
            group_score = 0.0
            group_features = self.feature_groups[group]
            
            for feature in group_features:
                feature_value = features.get(feature, 0)
                # 归一化特征值到0-1范围
                if isinstance(feature_value, (int, float)):
                    normalized_value = min(max(feature_value, 0), 1)
                else:
                    normalized_value = 1 if feature_value else 0
                
                # 对安全相关特征使用平方变换来放大风险
                if group == 'security':
                    normalized_value = normalized_value ** 2
                
                group_score += normalized_value
            
            # 计算组平均分数
            group_score = group_score / len(group_features)
            # 应用权重
            score += group_score * weight
        
        # 使用非线性变换来放大最终分数
        score = score ** 1.5
        
        return min(score, 1.0)  # 确保分数不超过1.0 