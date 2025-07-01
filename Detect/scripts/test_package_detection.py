#!/usr/bin/env python3
"""
测试包类型检测功能
"""

import sys
import os
import tempfile
import zipfile
import tarfile
import json

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.helpers import detect_package_type

def create_test_pypi_tar_gz():
    """创建一个PyPI包的tar.gz文件"""
    temp_dir = tempfile.mkdtemp()
    tar_path = os.path.join(temp_dir, 'test-pypi-package-1.0.0.tar.gz')
    
    with tarfile.open(tar_path, 'w:gz') as tar:
        # 添加setup.py
        setup_py = '''
from setuptools import setup, find_packages

setup(
    name="test-pypi-package",
    version="1.0.0",
    description="A test PyPI package",
    packages=find_packages(),
    python_requires=">=3.6",
)
'''
        setup_info = tarfile.TarInfo(name='test-pypi-package-1.0.0/setup.py')
        setup_info.size = len(setup_py.encode())
        tar.addfile(setup_info, fileobj=tarfile.io.BytesIO(setup_py.encode()))
        
        # 添加Python文件
        python_code = '''
def hello():
    print("Hello from PyPI package!")

if __name__ == "__main__":
    hello()
'''
        py_info = tarfile.TarInfo(name='test-pypi-package-1.0.0/test_package/__init__.py')
        py_info.size = len(python_code.encode())
        tar.addfile(py_info, fileobj=tarfile.io.BytesIO(python_code.encode()))
    
    return tar_path

def create_test_npm_tgz():
    """创建一个npm包的tgz文件"""
    temp_dir = tempfile.mkdtemp()
    tgz_path = os.path.join(temp_dir, 'test-npm-package-1.0.0.tgz')
    
    with tarfile.open(tgz_path, 'w:gz') as tar:
        # 添加package.json
        package_json = {
            "name": "test-npm-package",
            "version": "1.0.0",
            "description": "A test npm package",
            "main": "index.js",
            "scripts": {
                "test": "echo \"Error: no test specified\" && exit 1"
            },
            "author": "Test Author",
            "license": "MIT"
        }
        package_json_str = json.dumps(package_json, indent=2)
        
        pkg_info = tarfile.TarInfo(name='package/package.json')
        pkg_info.size = len(package_json_str.encode())
        tar.addfile(pkg_info, fileobj=tarfile.io.BytesIO(package_json_str.encode()))
        
        # 添加JavaScript文件
        js_code = '''
console.log("Hello from npm package!");

function testFunction() {
    return "This is a test function";
}

module.exports = { testFunction };
'''
        js_info = tarfile.TarInfo(name='package/index.js')
        js_info.size = len(js_code.encode())
        tar.addfile(js_info, fileobj=tarfile.io.BytesIO(js_code.encode()))
    
    return tgz_path

def create_test_pypi_zip():
    """创建一个PyPI包的zip文件"""
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, 'test-pypi-package-1.0.0.zip')
    
    with zipfile.ZipFile(zip_path, 'w') as zf:
        # 添加pyproject.toml
        pyproject_toml = '''
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "test-pypi-package"
version = "1.0.0"
description = "A test PyPI package"
requires-python = ">=3.6"
'''
        zf.writestr('test-pypi-package-1.0.0/pyproject.toml', pyproject_toml)
        
        # 添加Python文件
        python_code = '''
def hello():
    print("Hello from PyPI package!")
'''
        zf.writestr('test-pypi-package-1.0.0/src/test_package/__init__.py', python_code)
    
    return zip_path

def create_test_npm_zip():
    """创建一个npm包的zip文件"""
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, 'test-npm-package-1.0.0.zip')
    
    with zipfile.ZipFile(zip_path, 'w') as zf:
        # 添加package.json
        package_json = {
            "name": "test-npm-package",
            "version": "1.0.0",
            "description": "A test npm package",
            "main": "index.js"
        }
        zf.writestr('test-npm-package-1.0.0/package.json', json.dumps(package_json, indent=2))
        
        # 添加JavaScript文件
        js_code = '''
console.log("Hello from npm package!");
module.exports = { hello: () => console.log("Hello!") };
'''
        zf.writestr('test-npm-package-1.0.0/index.js', js_code)
    
    return zip_path

def test_package_detection():
    """测试包类型检测"""
    print("=== 测试包类型检测功能 ===\n")
    
    test_files = []
    
    try:
        # 创建测试文件
        print("1. 创建测试文件...")
        pypi_tar = create_test_pypi_tar_gz()
        npm_tgz = create_test_npm_tgz()
        pypi_zip = create_test_pypi_zip()
        npm_zip = create_test_npm_zip()
        
        test_files = [pypi_tar, npm_tgz, pypi_zip, npm_zip]
        
        print(f"   PyPI tar.gz: {os.path.basename(pypi_tar)}")
        print(f"   npm tgz: {os.path.basename(npm_tgz)}")
        print(f"   PyPI zip: {os.path.basename(pypi_zip)}")
        print(f"   npm zip: {os.path.basename(npm_zip)}")
        
        # 测试检测结果
        print("\n2. 测试包类型检测...")
        
        test_cases = [
            (pypi_tar, 'pypi', 'PyPI tar.gz包'),
            (npm_tgz, 'npm', 'npm tgz包'),
            (pypi_zip, 'pypi', 'PyPI zip包'),
            (npm_zip, 'npm', 'npm zip包')
        ]
        
        success_count = 0
        total_count = len(test_cases)
        
        for file_path, expected_type, description in test_cases:
            detected_type = detect_package_type(file_path)
            status = "✅" if detected_type == expected_type else "❌"
            print(f"   {status} {description}: 检测为 '{detected_type}' (期望: '{expected_type}')")
            
            if detected_type == expected_type:
                success_count += 1
        
        print(f"\n3. 测试结果: {success_count}/{total_count} 通过")
        
        if success_count == total_count:
            print("🎉 所有测试通过！包类型检测功能正常工作。")
        else:
            print("⚠️  部分测试失败，需要进一步调试。")
            
    except Exception as e:
        print(f"❌ 测试过程中出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理测试文件
        for file_path in test_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    # 清理临时目录
                    temp_dir = os.path.dirname(file_path)
                    if os.path.exists(temp_dir):
                        import shutil
                        shutil.rmtree(temp_dir)
                except:
                    pass

if __name__ == "__main__":
    test_package_detection()
