#!/usr/bin/env python3
"""
调试扫描任务
"""

import sys
import os
import sqlite3

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tasks import background_scan
from config.config import Config

def debug_scan_task(scan_id):
    """调试指定的扫描任务"""
    print(f"=== 调试扫描任务 ID: {scan_id} ===\n")
    
    # 获取扫描记录
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename, file_path, user_id, scan_status FROM scan_records WHERE id = ?', (scan_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        print(f"❌ 扫描记录 {scan_id} 不存在")
        return

    record_id, filename, file_path, user_id, scan_status = record
    scan_id = record_id  # 使用record_id避免变量名冲突
    print(f"扫描记录信息:")
    print(f"  ID: {scan_id}")
    print(f"  文件名: {filename}")
    print(f"  文件路径: {file_path}")
    print(f"  用户ID: {user_id}")
    print(f"  当前状态: {scan_status}")
    
    # 检查文件是否存在
    if not os.path.exists(file_path):
        print(f"❌ 文件不存在: {file_path}")
        
        # 尝试在上传目录中查找文件
        upload_dir = Config.UPLOAD_FOLDER
        potential_path = os.path.join(upload_dir, filename)
        if os.path.exists(potential_path):
            print(f"✅ 在上传目录找到文件: {potential_path}")
            file_path = potential_path
        else:
            print(f"❌ 在上传目录也未找到文件: {potential_path}")
            return
    else:
        print(f"✅ 文件存在: {file_path}")
    
    print(f"\n开始手动执行扫描任务...")
    
    try:
        # 手动执行后台扫描任务
        background_scan(scan_id, file_path, user_id)
        print("✅ 扫描任务执行完成")
        
        # 检查结果
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT scan_status, risk_level, confidence, error_message 
            FROM scan_records WHERE id = ?
        ''', (scan_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            status, risk_level, confidence, error_msg = result
            print(f"\n扫描结果:")
            print(f"  状态: {status}")
            print(f"  风险等级: {risk_level}")
            print(f"  置信度: {confidence}")
            print(f"  错误信息: {error_msg}")
        
    except Exception as e:
        print(f"❌ 扫描任务执行失败: {e}")
        import traceback
        traceback.print_exc()

def list_pending_scans():
    """列出所有待处理的扫描任务"""
    print("=== 待处理的扫描任务 ===\n")
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, filename, scan_status, created_at 
        FROM scan_records 
        WHERE scan_status = 'pending' 
        ORDER BY id DESC 
        LIMIT 10
    ''')
    records = cursor.fetchall()
    conn.close()
    
    if not records:
        print("没有待处理的扫描任务")
        return
    
    print(f"找到 {len(records)} 个待处理的扫描任务:")
    for record in records:
        scan_id, filename, status, created_at = record
        print(f"  ID: {scan_id}, 文件: {filename}, 状态: {status}, 创建时间: {created_at}")
    
    return [r[0] for r in records]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 调试指定的扫描任务
        scan_id = int(sys.argv[1])
        debug_scan_task(scan_id)
    else:
        # 列出待处理的任务
        pending_ids = list_pending_scans()
        
        if pending_ids:
            print(f"\n要调试最新的扫描任务吗？(ID: {pending_ids[0]})")
            choice = input("输入 'y' 确认，或输入具体的扫描ID: ").strip()
            
            if choice.lower() == 'y':
                debug_scan_task(pending_ids[0])
            elif choice.isdigit():
                debug_scan_task(int(choice))
            else:
                print("已取消")
