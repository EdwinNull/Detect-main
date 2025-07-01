#!/usr/bin/env python3
"""
测试样本上传修复
"""

import sys
import os
import tempfile
import zipfile
import json
import hashlib

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.extractor import FeatureExtractor
from app.utils.helpers import detect_package_type
from werkzeug.utils import secure_filename
import sqlite3
from config.config import Config

def create_test_zip():
    """创建一个测试用的zip文件"""
    # 创建临时文件
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, 'test_package.zip')
    
    # 创建一个简单的zip文件
    with zipfile.ZipFile(zip_path, 'w') as zf:
        # 添加package.json
        package_json = '''
{
    "name": "test-package",
    "version": "1.0.0",
    "description": "A test package",
    "main": "index.js",
    "scripts": {
        "test": "echo \\"Error: no test specified\\" && exit 1"
    },
    "author": "Test Author",
    "license": "MIT"
}
'''
        zf.writestr('package.json', package_json)
        
        # 添加index.js
        index_js = '''
console.log("Hello, World!");

function testFunction() {
    return "This is a test function";
}

module.exports = { testFunction };
'''
        zf.writestr('index.js', index_js)
    
    return zip_path

def test_upload_logic():
    """测试上传逻辑"""
    print("=== 测试样本上传逻辑 ===")
    
    # 创建测试文件
    test_file = create_test_zip()
    print(f"创建测试文件: {test_file}")
    
    try:
        # 模拟上传逻辑
        filename = secure_filename(os.path.basename(test_file))
        samples_dir = os.path.join(Config.UPLOAD_FOLDER, 'samples')
        os.makedirs(samples_dir, exist_ok=True)
        
        # 复制文件到samples目录
        import shutil
        file_path = os.path.join(samples_dir, filename)
        shutil.copy2(test_file, file_path)
        print(f"文件复制到: {file_path}")
        
        # 计算文件哈希
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"文件哈希: {file_hash}")
        
        # 自动检测包类型
        package_type = detect_package_type(file_path)
        print(f"包类型: {package_type}")
        
        # 提取特征
        extractor = FeatureExtractor()
        features = extractor.extract_features(file_path)
        print(f"特征提取成功，共 {len(features)} 个特征")
        
        # 确保features是字典类型
        if not isinstance(features, dict):
            features = {}
        
        # 测试数据库插入
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        
        malware_status = 'benign'
        description = '测试上传的样本文件'
        
        cursor.execute('''
            INSERT INTO samples (filename, file_path, file_size, file_hash, type, package_type, description, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filename,
            file_path,
            os.path.getsize(file_path),
            file_hash,
            malware_status,
            package_type,
            description,
            json.dumps(features)
        ))
        
        sample_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"✅ 样本成功插入数据库，ID: {sample_id}")
        
        # 验证插入的数据
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM samples WHERE id = ?', (sample_id,))
        sample = cursor.fetchone()
        conn.close()
        
        if sample:
            print("✅ 数据库验证成功")
            print(f"  文件名: {sample[1]}")
            print(f"  文件路径: {sample[2]}")
            print(f"  文件大小: {sample[6]}")
            print(f"  文件哈希: {sample[7]}")
            print(f"  类型: {sample[3]}")
            print(f"  包类型: {sample[4]}")
            print(f"  描述: {sample[8]}")
            print(f"  特征数据长度: {len(sample[9]) if sample[9] else 0}")
        else:
            print("❌ 数据库验证失败")
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理测试文件
        if os.path.exists(test_file):
            os.remove(test_file)
        # 清理临时目录
        temp_dir = os.path.dirname(test_file)
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    test_upload_logic()
