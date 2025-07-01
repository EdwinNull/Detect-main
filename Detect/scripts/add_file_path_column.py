#!/usr/bin/env python3
"""
为scan_records表添加file_path列
"""

import sys
import os
import sqlite3

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import Config

def add_file_path_column():
    """为scan_records表添加file_path列"""
    print("=== 添加file_path列到scan_records表 ===\n")
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # 检查列是否已存在
        cursor.execute('PRAGMA table_info(scan_records)')
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'file_path' in column_names:
            print("✅ file_path列已存在，无需添加")
            return
        
        # 添加file_path列
        cursor.execute('ALTER TABLE scan_records ADD COLUMN file_path TEXT')
        print("✅ 成功添加file_path列")
        
        # 为现有记录填充file_path
        cursor.execute('SELECT id, filename FROM scan_records WHERE file_path IS NULL')
        records = cursor.fetchall()
        
        if records:
            print(f"正在为 {len(records)} 条现有记录填充file_path...")
            
            for scan_id, filename in records:
                # 推断文件路径
                file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
                cursor.execute('UPDATE scan_records SET file_path = ? WHERE id = ?', 
                             (file_path, scan_id))
            
            print(f"✅ 已为 {len(records)} 条记录填充file_path")
        
        conn.commit()
        print("✅ 数据库更新完成")
        
    except Exception as e:
        print(f"❌ 更新失败: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    add_file_path_column()
