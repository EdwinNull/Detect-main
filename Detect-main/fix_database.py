#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库修复脚本
修复现有数据库中缺失的列
"""

import sqlite3
import os
from datetime import datetime
from config.config import Config

def fix_database():
    """修复数据库结构"""
    print("开始修复数据库...")
    
    db_path = Config.DATABASE_PATH
    if not os.path.exists(db_path):
        print(f"数据库文件不存在: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # 1. 修复 users 表
        print("检查 users 表...")
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'created_at' not in columns:
            print("添加 created_at 列到 users 表...")
            # SQLite不支持在ALTER TABLE时添加带有非常量默认值的列
            # 先添加列，然后更新现有记录
            cursor.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP")
            # 为现有记录设置当前时间
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("UPDATE users SET created_at = ? WHERE created_at IS NULL", (current_time,))
            print("✓ created_at 列添加成功")
        else:
            print("✓ users 表已包含 created_at 列")
        
        # 2. 修复 scan_records 表
        print("检查 scan_records 表...")
        cursor.execute("PRAGMA table_info(scan_records)")
        columns = [column[1] for column in cursor.fetchall()]
        
        missing_columns = []
        if 'malicious_code_snippet' not in columns:
            missing_columns.append('malicious_code_snippet TEXT')
        if 'code_location' not in columns:
            missing_columns.append('code_location TEXT')
        if 'malicious_action' not in columns:
            missing_columns.append('malicious_action TEXT')
        if 'technical_details' not in columns:
            missing_columns.append('technical_details TEXT')
        
        for column_def in missing_columns:
            column_name = column_def.split()[0]
            print(f"添加 {column_name} 列到 scan_records 表...")
            cursor.execute(f"ALTER TABLE scan_records ADD COLUMN {column_def}")
            print(f"✓ {column_name} 列添加成功")
        
        if not missing_columns:
            print("✓ scan_records 表结构完整")
        
        # 3. 修复 package_encyclopedia 表
        print("检查 package_encyclopedia 表...")
        cursor.execute("PRAGMA table_info(package_encyclopedia)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'tags' not in columns:
            print("添加 tags 列到 package_encyclopedia 表...")
            cursor.execute("ALTER TABLE package_encyclopedia ADD COLUMN tags TEXT")
            print("✓ tags 列添加成功")
        else:
            print("✓ package_encyclopedia 表已包含 tags 列")
        
        # 4. 修复 anomaly_reports 表
        print("检查 anomaly_reports 表...")
        cursor.execute("PRAGMA table_info(anomaly_reports)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'title' not in columns:
            print("添加 title 列到 anomaly_reports 表...")
            cursor.execute("ALTER TABLE anomaly_reports ADD COLUMN title TEXT")
            print("✓ title 列添加成功")
        
        if 'description' not in columns:
            print("添加 description 列到 anomaly_reports 表...")
            cursor.execute("ALTER TABLE anomaly_reports ADD COLUMN description TEXT")
            print("✓ description 列添加成功")
        
        # 数据迁移：将旧的 reason 数据迁移到 description
        if 'reason' in columns and 'description' in columns:
            cursor.execute("UPDATE anomaly_reports SET description = reason WHERE description IS NULL")
            print("✓ 数据迁移完成")
        
        # 提交更改
        conn.commit()
        print("\n数据库修复完成！")
        
        # 显示修复后的表结构
        print("\n修复后的表结构:")
        tables = ['users', 'scan_records', 'package_encyclopedia', 'anomaly_reports']
        for table in tables:
            print(f"\n{table} 表:")
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
        
    except sqlite3.Error as e:
        print(f"数据库操作失败: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    fix_database() 