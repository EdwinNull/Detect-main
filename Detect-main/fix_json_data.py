#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库JSON数据修复脚本
修复数据库中无效的JSON数据
"""

import sqlite3
import json
import os
from config.config import Config

def fix_json_data():
    """修复数据库中的无效JSON数据"""
    print("开始修复数据库中的JSON数据...")
    
    db_path = Config.DATABASE_PATH
    if not os.path.exists(db_path):
        print(f"数据库文件不存在: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # 1. 修复 scan_records 表中的 xgboost_result 和 llm_result
        print("检查 scan_records 表...")
        cursor.execute("SELECT id, xgboost_result, llm_result FROM scan_records")
        records = cursor.fetchall()
        
        fixed_count = 0
        for record_id, xgboost_result, llm_result in records:
            needs_update = False
            new_xgboost = xgboost_result
            new_llm = llm_result
            
            # 检查 xgboost_result
            if xgboost_result:
                try:
                    json.loads(xgboost_result)
                except (json.JSONDecodeError, TypeError):
                    print(f"修复 scan_record {record_id} 的 xgboost_result")
                    new_xgboost = '{}'
                    needs_update = True
            
            # 检查 llm_result
            if llm_result:
                try:
                    json.loads(llm_result)
                except (json.JSONDecodeError, TypeError):
                    print(f"修复 scan_record {record_id} 的 llm_result")
                    new_llm = '{}'
                    needs_update = True
            
            if needs_update:
                cursor.execute(
                    "UPDATE scan_records SET xgboost_result = ?, llm_result = ? WHERE id = ?",
                    (new_xgboost, new_llm, record_id)
                )
                fixed_count += 1
        
        print(f"修复了 {fixed_count} 条 scan_records 记录")
        
        # 2. 修复 features 表中的 feature_data
        print("检查 features 表...")
        cursor.execute("SELECT id, feature_data FROM features")
        features = cursor.fetchall()
        
        fixed_features = 0
        for feature_id, feature_data in features:
            if feature_data:
                try:
                    json.loads(feature_data)
                except (json.JSONDecodeError, TypeError):
                    print(f"修复 feature {feature_id} 的 feature_data")
                    cursor.execute(
                        "UPDATE features SET feature_data = ? WHERE id = ?",
                        ('{}', feature_id)
                    )
                    fixed_features += 1
        
        print(f"修复了 {fixed_features} 条 features 记录")
        
        # 提交更改
        conn.commit()
        print(f"\nJSON数据修复完成！")
        print(f"总共修复了 {fixed_count + fixed_features} 条记录")
        
    except sqlite3.Error as e:
        print(f"数据库操作失败: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    fix_json_data() 