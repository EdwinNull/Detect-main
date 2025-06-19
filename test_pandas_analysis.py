#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
from pathlib import Path

# 添加项目路径
sys.path.append('Detect-main')

from app.services.extractor import FeatureExtractor
from app.services.classifier import SecurityClassifier

def analyze_pandas_package():
    """分析pandas包的特征提取和分类过程"""
    
    # 初始化特征提取器和分类器
    extractor = FeatureExtractor()
    classifier = SecurityClassifier()
    
    # pandas包路径
    pandas_path = "Detect-main/pandas-2.3.0.tar.gz"
    
    if not os.path.exists(pandas_path):
        print(f"错误：找不到pandas包文件 {pandas_path}")
        return
    
    print("=" * 60)
    print("开始分析pandas包...")
    print("=" * 60)
    
    # 1. 特征提取
    print("\n1. 特征提取阶段")
    print("-" * 30)
    
    features = extractor.extract_features(pandas_path)
    
    if not features:
        print("特征提取失败")
        return
    
    print(f"提取到 {len(features)} 个特征")
    
    # 2. 显示关键特征
    print("\n2. 关键特征分析")
    print("-" * 30)
    
    key_features = {
        '基础统计': [
            'Number of Words in source code',
            'Number of lines in source code'
        ],
        '安全特征': [
            'Number of base64 chunks in source code',
            'Number of IP adress in source code',
            'Number of sospicious token in source code'
        ],
        '文件类型': [
            '.py', '.pyc', '.pkl', '.pickle', '.exe', '.dll', '.so'
        ],
        '熵特征': [
            'shannon mean ID source code',
            'shannon max ID source code',
            'shannon mean string source code',
            'shannon max string source code'
        ],
        '字符比率': [
            'plus ratio max',
            'eq ratio max',
            'bracket ratio max'
        ]
    }
    
    for category, feature_list in key_features.items():
        print(f"\n{category}:")
        for feature in feature_list:
            value = features.get(feature, 0)
            print(f"  {feature}: {value}")
    
    # 3. 白名单检查
    print("\n3. 白名单检查")
    print("-" * 30)
    
    is_whitelisted = classifier._is_whitelisted_package(features)
    print(f"是否在白名单中: {is_whitelisted}")
    
    # 4. 模型预测
    print("\n4. 模型预测")
    print("-" * 30)
    
    result = classifier.predict(features)
    
    print(f"预测结果: {result}")
    
    # 5. 风险评分分析
    print("\n5. 风险评分详细分析")
    print("-" * 30)
    
    # 手动计算风险评分
    model_proba = result.get('risk_score', 0.5)
    risk_score = classifier._calculate_csv_based_risk_score(features, model_proba)
    
    print(f"模型概率: {model_proba:.3f}")
    print(f"计算的风险分数: {risk_score:.3f}")
    
    # 分析各个组成部分
    security_features = [
        'Number of base64 chunks in source code',
        'Number of IP adress in source code',
        'Number of sospicious token in source code',
        'Number of base64 chunks in metadata',
        'Number of IP adress in metadata',
        'Number of sospicious token in metadata'
    ]
    
    security_score = 0.0
    for feature in security_features:
        value = features.get(feature, 0)
        if isinstance(value, (int, float)) and value > 0:
            security_score += min(value / 10.0, 1.0)
    security_score = min(security_score / len(security_features), 1.0)
    
    print(f"安全特征分数: {security_score:.3f}")
    
    # 熵特征分析
    entropy_features = [
        'shannon mean ID source code',
        'shannon max ID source code',
        'shannon mean string source code',
        'shannon max string source code'
    ]
    
    entropy_score = 0.0
    for feature in entropy_features:
        value = features.get(feature, 0)
        if isinstance(value, (int, float)) and value > 0:
            entropy_score += min(value / 2.0, 1.0)
    entropy_score = min(entropy_score / len(entropy_features), 1.0)
    
    print(f"熵特征分数: {entropy_score:.3f}")
    
    # 可疑文件类型分析
    suspicious_files = ['.exe', '.dll', '.so', '.bat', '.sh']
    suspicious_file_score = 0.0
    for file_type in suspicious_files:
        value = features.get(file_type, 0)
        if isinstance(value, (int, float)) and value > 0:
            suspicious_file_score += min(value / 5.0, 1.0)
    suspicious_file_score = min(suspicious_file_score / len(suspicious_files), 1.0)
    
    print(f"可疑文件类型分数: {suspicious_file_score:.3f}")
    
    # 6. 问题诊断
    print("\n6. 问题诊断")
    print("-" * 30)
    
    issues = []
    
    # 检查是否有可疑token
    suspicious_tokens = features.get('Number of sospicious token in source code', 0)
    if suspicious_tokens > 0:
        issues.append(f"发现 {suspicious_tokens} 个可疑token")
    
    # 检查熵值是否过高
    max_entropy = features.get('shannon max ID source code', 0)
    if max_entropy > 4.0:
        issues.append(f"标识符熵值过高: {max_entropy:.2f}")
    
    # 检查是否有可疑文件类型
    for file_type in ['.exe', '.dll', '.so', '.bat', '.sh']:
        count = features.get(file_type, 0)
        if count > 0:
            issues.append(f"发现 {count} 个 {file_type} 文件")
    
    if issues:
        print("发现以下可能导致误判的问题:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("未发现明显的问题特征")
    
    # 7. 建议修复
    print("\n7. 修复建议")
    print("-" * 30)
    
    if not is_whitelisted:
        print("建议将pandas添加到白名单中")
    
    if suspicious_tokens > 0:
        print("建议检查可疑token的正则表达式，可能需要调整")
    
    if max_entropy > 4.0:
        print("建议调整熵值阈值，或者为知名包添加特殊处理")
    
    print("\n" + "=" * 60)
    print("分析完成")
    print("=" * 60)

if __name__ == "__main__":
    analyze_pandas_package() 