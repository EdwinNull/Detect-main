import os
import json
import sqlite3
import hashlib
import zipfile
import tarfile
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from flask import current_app, g
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import joblib
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings('ignore')

# 导入配置
from config.config import Config

def format_size(size_in_bytes):
    """格式化文件大小"""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

def detect_package_type(file_path):
    """检测包类型"""
    if not os.path.exists(file_path):
        return 'unknown'

    filename = os.path.basename(file_path).lower()

    # 直接通过文件扩展名判断的情况
    if filename.endswith('.whl'):
        return 'pypi'
    elif filename.endswith('.jar'):
        return 'maven'
    elif filename.endswith('.gem'):
        return 'rubygems'

    # 需要检查内容的压缩包格式
    elif filename.endswith('.zip'):
        return _detect_zip_package_type(file_path)
    elif filename.endswith('.tgz') or filename.endswith('.tar.gz') or filename.endswith('.tar'):
        return _detect_tar_package_type(file_path)
    elif filename.endswith('.py'):
        return 'pypi'
    else:
        return 'unknown'

def _detect_zip_package_type(file_path):
    """检测ZIP文件的包类型"""
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()

            # 检查PyPI包特征文件
            pypi_markers = ['setup.py', 'pyproject.toml', 'setup.cfg', 'PKG-INFO', 'METADATA']
            if any(any(name.endswith(marker) for name in file_list) for marker in pypi_markers):
                return 'pypi'

            # 检查npm包特征文件
            if any(name.endswith('package.json') for name in file_list):
                return 'npm'

            # 检查Maven包特征文件
            if any(name.endswith('pom.xml') or name.endswith('build.gradle') for name in file_list):
                return 'maven'

            # 检查Ruby包特征文件
            if any(name.endswith('.gemspec') for name in file_list):
                return 'rubygems'

            # 根据文件内容推测
            if any(name.endswith('.py') for name in file_list):
                return 'pypi'
            elif any(name.endswith('.js') or name.endswith('.ts') for name in file_list):
                return 'npm'
            elif any(name.endswith('.java') for name in file_list):
                return 'maven'
            elif any(name.endswith('.rb') for name in file_list):
                return 'rubygems'

            return 'zip'
    except Exception as e:
        print(f"检测ZIP包类型时出错: {e}")
        return 'zip'

def _detect_tar_package_type(file_path):
    """检测TAR文件的包类型"""
    try:
        import tarfile
        with tarfile.open(file_path, 'r:*') as tar:
            names = tar.getnames()

            # 检查PyPI包特征文件
            pypi_markers = ['setup.py', 'pyproject.toml', 'setup.cfg', 'PKG-INFO', 'METADATA']
            if any(any(name.endswith(marker) for name in names) for marker in pypi_markers):
                return 'pypi'

            # 检查npm包特征文件
            if any(name.endswith('package.json') for name in names):
                return 'npm'

            # 检查Maven包特征文件
            if any(name.endswith('pom.xml') or name.endswith('build.gradle') for name in names):
                return 'maven'

            # 检查Ruby包特征文件
            if any(name.endswith('.gemspec') for name in names):
                return 'rubygems'

            # 根据文件内容推测
            if any(name.endswith('.py') for name in names):
                return 'pypi'
            elif any(name.endswith('.js') or name.endswith('.ts') for name in names):
                return 'npm'
            elif any(name.endswith('.java') for name in names):
                return 'maven'
            elif any(name.endswith('.rb') for name in names):
                return 'rubygems'

            return 'unknown'
    except Exception as e:
        print(f"检测TAR包类型时出错: {e}")
        return 'unknown'

def safe_json_loads(data):
    """
    安全地解析JSON数据
    如果解析失败，返回空字典
    """
    if not data:
        return {}
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return {}

def safe_json_dumps(data):
    """
    安全地序列化JSON数据
    如果序列化失败，返回空字符串
    """
    try:
        return json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError):
        return ""

def calculate_file_hash(file_path):
    """计算文件MD5哈希值"""
    if not os.path.exists(file_path):
        return None
    
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None

def extract_archive(archive_path, extract_to=None):
    """解压压缩文件"""
    if not os.path.exists(archive_path):
        return None
    
    if extract_to is None:
        extract_to = tempfile.mkdtemp()
    
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif archive_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to)
        elif archive_path.endswith('.tar'):
            with tarfile.open(archive_path, 'r') as tar_ref:
                tar_ref.extractall(extract_to)
        else:
            return None
        
        return extract_to
    except Exception as e:
        print(f"解压失败: {e}")
        return None

def cleanup_temp_files(temp_dir):
    """清理临时文件"""
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"清理临时文件失败: {e}")

def get_file_size_mb(file_path):
    """获取文件大小（MB）"""
    if not os.path.exists(file_path):
        return 0
    
    size_bytes = os.path.getsize(file_path)
    return round(size_bytes / (1024 * 1024), 2)

def is_valid_filename(filename):
    """检查文件名是否有效"""
    if not filename:
        return False
    
    # 检查是否包含危险字符
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/']
    return not any(char in filename for char in dangerous_chars)

def get_setting(key, default=None):
    """从数据库获取系统设置"""
    from config import Config
    import sqlite3
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return result[0]
    return default
