#!/usr/bin/env python3
"""
测试样本上传功能
"""

import sys
import os
import requests
import tempfile
import zipfile

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
        
        # 添加README.md
        readme = '''
# Test Package

This is a test package for testing the upload functionality.

## Installation

```bash
npm install test-package
```

## Usage

```javascript
const { testFunction } = require('test-package');
console.log(testFunction());
```
'''
        zf.writestr('README.md', readme)
    
    return zip_path

def test_upload_via_api():
    """通过API测试上传功能"""
    print("=== 测试样本上传API ===")
    
    # 创建测试文件
    test_file = create_test_zip()
    print(f"创建测试文件: {test_file}")
    
    try:
        # 准备上传数据
        files = {
            'samples': ('test_package.zip', open(test_file, 'rb'), 'application/zip')
        }
        
        data = {
            'sample_type': 'benign',
            'description': '测试上传的样本文件'
        }
        
        # 发送请求
        url = 'http://localhost:5000/admin/samples/upload'
        
        print("发送上传请求...")
        response = requests.post(url, files=files, data=data)
        
        print(f"响应状态码: {response.status_code}")
        print(f"响应头: {dict(response.headers)}")
        print(f"响应内容类型: {response.headers.get('content-type', 'unknown')}")
        
        # 打印响应内容的前500个字符
        response_text = response.text
        print(f"响应内容 (前500字符): {response_text[:500]}")
        
        if response.headers.get('content-type', '').startswith('application/json'):
            try:
                json_data = response.json()
                print(f"JSON响应: {json_data}")
            except Exception as e:
                print(f"解析JSON失败: {e}")
        else:
            print("响应不是JSON格式")
            
    except Exception as e:
        print(f"请求失败: {e}")
    finally:
        # 清理测试文件
        if os.path.exists(test_file):
            os.remove(test_file)
        # 清理临时目录
        temp_dir = os.path.dirname(test_file)
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir)

def test_feature_extraction():
    """测试特征提取功能"""
    print("\n=== 测试特征提取功能 ===")
    
    from app.services.extractor import FeatureExtractor
    
    # 创建测试文件
    test_file = create_test_zip()
    print(f"创建测试文件: {test_file}")
    
    try:
        extractor = FeatureExtractor()
        print("开始特征提取...")
        
        features = extractor.extract_features(test_file)
        
        if features:
            print(f"特征提取成功，共提取 {len(features)} 个特征")
            print("前10个特征:")
            for i, (key, value) in enumerate(features.items()):
                if i >= 10:
                    break
                print(f"  {key}: {value}")
        else:
            print("特征提取失败")
            
    except Exception as e:
        print(f"特征提取异常: {e}")
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
    test_feature_extraction()
    print("\n" + "="*50 + "\n")
    test_upload_via_api()
