#!/usr/bin/env python3
"""
测试样本上传功能（包含登录）
"""

import requests
import tempfile
import zipfile
import os
import json

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

def test_upload_with_login():
    """测试带登录的上传功能"""
    print("=== 测试样本上传API（带登录） ===")
    
    # 创建会话
    session = requests.Session()
    base_url = 'http://localhost:5000'
    
    try:
        # 1. 先登录
        print("1. 尝试登录...")
        login_data = {
            'username': 'admin',
            'password': 'admin123'
        }
        
        login_response = session.post(f'{base_url}/auth/login', data=login_data)
        print(f"登录响应状态码: {login_response.status_code}")
        
        if login_response.status_code != 200:
            print("❌ 登录失败")
            return
        
        # 检查是否成功登录（通过重定向或响应内容判断）
        if 'login' in login_response.url.lower() or '登录' in login_response.text:
            print("❌ 登录失败，仍在登录页面")
            return
        
        print("✅ 登录成功")
        
        # 2. 创建测试文件
        test_file = create_test_zip()
        print(f"创建测试文件: {test_file}")
        
        # 3. 上传文件
        print("2. 上传文件...")
        with open(test_file, 'rb') as f:
            files = {'files': (os.path.basename(test_file), f, 'application/zip')}
            data = {'description': '测试上传的样本文件'}
            
            upload_response = session.post(f'{base_url}/admin/samples/upload', 
                                         files=files, data=data)
        
        print(f"上传响应状态码: {upload_response.status_code}")
        print(f"响应头: {dict(upload_response.headers)}")
        print(f"响应内容类型: {upload_response.headers.get('content-type', 'unknown')}")
        
        # 检查响应内容
        if 'application/json' in upload_response.headers.get('content-type', ''):
            try:
                response_json = upload_response.json()
                print("✅ 收到JSON响应:")
                print(json.dumps(response_json, indent=2, ensure_ascii=False))
                
                if response_json.get('success'):
                    print("✅ 上传成功！")
                else:
                    print(f"❌ 上传失败: {response_json.get('error', '未知错误')}")
                    
            except json.JSONDecodeError as e:
                print(f"❌ JSON解析失败: {e}")
                print(f"响应内容 (前500字符): {upload_response.text[:500]}")
        else:
            print("❌ 响应不是JSON格式")
            print(f"响应内容 (前500字符): {upload_response.text[:500]}")
            
    except requests.exceptions.ConnectionError:
        print("❌ 无法连接到服务器，请确保Flask应用正在运行")
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理测试文件
        if 'test_file' in locals() and os.path.exists(test_file):
            try:
                os.remove(test_file)
                # 清理临时目录
                temp_dir = os.path.dirname(test_file)
                if os.path.exists(temp_dir):
                    import shutil
                    shutil.rmtree(temp_dir)
            except:
                pass

if __name__ == "__main__":
    test_upload_with_login()
