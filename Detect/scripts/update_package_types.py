#!/usr/bin/env python3
"""
更新数据库中样本的包类型
"""

import sys
import os
import sqlite3

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.helpers import detect_package_type
from config.config import Config

def update_package_types():
    """更新数据库中所有样本的包类型"""
    print("=== 更新样本包类型 ===\n")
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # 获取所有样本
        cursor.execute('SELECT id, filename, file_path, package_type FROM samples')
        samples = cursor.fetchall()
        
        if not samples:
            print("数据库中没有样本需要更新")
            return
        
        print(f"找到 {len(samples)} 个样本需要检查")
        print("=" * 60)
        
        updated_count = 0
        error_count = 0
        
        for sample_id, filename, file_path, current_type in samples:
            print(f"\n处理样本 ID {sample_id}: {filename}")
            print(f"  当前类型: {current_type}")
            print(f"  文件路径: {file_path}")
            
            # 检查文件是否存在
            if not os.path.exists(file_path):
                print(f"  ❌ 文件不存在，跳过")
                error_count += 1
                continue
            
            # 重新检测包类型
            try:
                new_type = detect_package_type(file_path)
                print(f"  检测结果: {new_type}")
                
                if new_type != current_type:
                    # 更新数据库
                    cursor.execute('UPDATE samples SET package_type = ? WHERE id = ?', 
                                 (new_type, sample_id))
                    print(f"  ✅ 更新: {current_type} -> {new_type}")
                    updated_count += 1
                else:
                    print(f"  ✓ 类型正确，无需更新")
                    
            except Exception as e:
                print(f"  ❌ 检测失败: {e}")
                error_count += 1
        
        # 提交更改
        conn.commit()
        
        print("\n" + "=" * 60)
        print(f"更新完成:")
        print(f"  总样本数: {len(samples)}")
        print(f"  已更新: {updated_count}")
        print(f"  错误: {error_count}")
        print(f"  无需更新: {len(samples) - updated_count - error_count}")
        
        # 显示更新后的统计
        print("\n更新后的包类型统计:")
        cursor.execute('''
            SELECT package_type, COUNT(*) as count 
            FROM samples 
            GROUP BY package_type 
            ORDER BY count DESC
        ''')
        stats = cursor.fetchall()
        
        for pkg_type, count in stats:
            print(f"  {pkg_type}: {count} 个")
            
    except Exception as e:
        print(f"❌ 更新过程中出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

def verify_specific_samples():
    """验证特定样本的包类型检测"""
    print("\n=== 验证特定样本 ===")
    
    # 检查一些具体的文件
    test_files = [
        'temp/uploads/samples/test_package.zip',
        'temp/uploads/samples/adm3-1.8.0.tar.gz',
        'temp/uploads/samples/adm4-1.9.0.tar.gz',
        'temp/uploads/samples/admask-10.81.tar.gz'
    ]
    
    for file_path in test_files:
        if os.path.exists(file_path):
            detected_type = detect_package_type(file_path)
            print(f"  {os.path.basename(file_path)}: {detected_type}")
        else:
            print(f"  {os.path.basename(file_path)}: 文件不存在")

if __name__ == "__main__":
    update_package_types()
    verify_specific_samples()
