#!/usr/bin/env python3
"""
测试模型加载和预测功能
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.classifier import SecurityClassifier
import numpy as np

def test_model_loading():
    """测试模型加载"""
    print("=== 测试模型加载 ===")
    
    models = ['js_model', 'py_model', 'cross_language', 'xgboost']
    
    for model_type in models:
        print(f"\n测试 {model_type} 模型:")
        try:
            classifier = SecurityClassifier(model_type=model_type)
            if classifier.is_trained:
                print(f"✅ {model_type} 模型加载成功")
                print(f"   模型类型: {type(classifier.model)}")
                print(f"   特征数量: {len(classifier.feature_names)}")
            else:
                print(f"❌ {model_type} 模型加载失败")
        except Exception as e:
            print(f"❌ {model_type} 模型测试异常: {str(e)}")

def test_model_prediction():
    """测试模型预测功能"""
    print("\n=== 测试模型预测 ===")
    
    # 创建测试特征
    test_features = {
        'package_name': 'test-package',
        'version': '1.0.0',
        'file_count': 10,
        'total_size': 1024,
        'has_suspicious_files': 0,
        'entropy_score': 0.5,
        'complexity_score': 0.3,
        'dependency_count': 5,
        'has_network_access': 0,
        'has_file_operations': 1,
        'has_eval_functions': 0,
        'has_obfuscation': 0,
        'maintainer_reputation': 0.8,
        'download_count': 1000,
        'age_days': 365,
        'has_tests': 1,
        'has_documentation': 1,
        'license_type': 'MIT',
        'has_vulnerabilities': 0,
        'security_score': 0.7
    }
    
    # 补充特征到141个
    for i in range(len(test_features), 141):
        test_features[f'feature_{i}'] = np.random.random()
    
    models = ['js_model', 'py_model', 'cross_language', 'xgboost']
    
    for model_type in models:
        print(f"\n测试 {model_type} 预测:")
        try:
            classifier = SecurityClassifier(model_type=model_type)
            if classifier.is_trained:
                result = classifier.predict(test_features)
                print(f"✅ 预测成功:")
                print(f"   预测结果: {'恶意' if result['prediction'] == 1 else '正常'}")
                print(f"   风险等级: {result['risk_level']}")
                print(f"   风险分数: {result['risk_score']:.3f}")
                print(f"   置信度: {result['confidence']:.3f}")
            else:
                print(f"❌ 模型未训练，无法预测")
        except Exception as e:
            print(f"❌ {model_type} 预测异常: {str(e)}")

def test_different_risk_scenarios():
    """测试不同风险场景"""
    print("\n=== 测试不同风险场景 ===")
    
    scenarios = {
        '低风险包': {
            'package_name': 'lodash',
            'version': '4.17.21',
            'file_count': 50,
            'total_size': 2048,
            'has_suspicious_files': 0,
            'entropy_score': 0.3,
            'complexity_score': 0.2,
            'dependency_count': 0,
            'has_network_access': 0,
            'has_file_operations': 0,
            'has_eval_functions': 0,
            'has_obfuscation': 0,
            'maintainer_reputation': 0.9,
            'download_count': 10000000,
            'age_days': 2000,
            'has_tests': 1,
            'has_documentation': 1,
            'license_type': 'MIT',
            'has_vulnerabilities': 0,
            'security_score': 0.9
        },
        '高风险包': {
            'package_name': 'suspicious-package',
            'version': '0.0.1',
            'file_count': 5,
            'total_size': 512,
            'has_suspicious_files': 1,
            'entropy_score': 0.9,
            'complexity_score': 0.8,
            'dependency_count': 20,
            'has_network_access': 1,
            'has_file_operations': 1,
            'has_eval_functions': 1,
            'has_obfuscation': 1,
            'maintainer_reputation': 0.1,
            'download_count': 10,
            'age_days': 1,
            'has_tests': 0,
            'has_documentation': 0,
            'license_type': 'Unknown',
            'has_vulnerabilities': 1,
            'security_score': 0.1
        }
    }
    
    classifier = SecurityClassifier(model_type='xgboost')
    
    for scenario_name, features in scenarios.items():
        print(f"\n{scenario_name}:")
        
        # 补充特征到141个
        full_features = features.copy()
        for i in range(len(full_features), 141):
            full_features[f'feature_{i}'] = np.random.random() * 0.1  # 低随机值
        
        try:
            result = classifier.predict(full_features)
            print(f"  预测结果: {'恶意' if result['prediction'] == 1 else '正常'}")
            print(f"  风险等级: {result['risk_level']}")
            print(f"  风险分数: {result['risk_score']:.3f}")
            print(f"  置信度: {result['confidence']:.3f}")
        except Exception as e:
            print(f"  预测异常: {str(e)}")

if __name__ == "__main__":
    test_model_loading()
    test_model_prediction()
    test_different_risk_scenarios()
    print("\n=== 测试完成 ===")
