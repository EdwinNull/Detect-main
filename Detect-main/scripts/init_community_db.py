#!/usr/bin/env python3
"""
社区功能数据库初始化脚本
"""
import sqlite3
import os
import sys
import json
from datetime import datetime
import hashlib
import uuid
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import Config

from app.models.community_models import CommunityPost

def init_community_database():
    """初始化社区数据库表"""
    print("🔧 正在初始化社区数据库...")
    
    try:
        # 创建社区相关数据表
        CommunityPost.create_tables()
        print("✅ 社区数据表创建成功！")
        
        # 添加一些示例数据
        add_sample_data()
        print("✅ 示例数据添加成功！")
        
        print("🎉 社区数据库初始化完成！")
        
    except Exception as e:
        print(f"❌ 初始化失败: {e}")
        return False
    
    return True

def add_sample_data():
    """添加示例数据"""
    from app.models.db_models import User
    
    # 获取或创建测试用户
    test_user = User.get_by_username('admin')
    if not test_user:
        print("⚠️  未找到admin用户，跳过示例数据添加")
        return
    
    # 添加示例帖子
    sample_posts = [
        {
            'title': '发现可疑的npm包：fake-login-form',
            'content': '''检测发现：fake-login-form

风险等级：high
置信度：95.2%

详细分析：
这个npm包伪装成登录表单组件，但实际上会收集用户的登录凭据并发送到远程服务器。包名故意模仿了流行的login-form组件，容易误导开发者。

主要特征：
1. 包名具有迷惑性，模仿知名组件
2. 代码中包含数据收集和网络请求功能
3. 文档描述与实际功能不符
4. 发布者账号为新注册，无其他可信项目

防护建议：
1. 仔细检查包名，避免使用相似名称的包
2. 查看包的下载量、评分和评论
3. 检查发布者的其他项目和历史
4. 使用安全扫描工具进行检测
5. 在测试环境中先验证包的功能''',
            'package_name': 'fake-login-form',
            'package_type': 'npm',
            'risk_level': 'high',
            'confidence': 95.2
        },
        {
            'title': 'PyPI恶意包分析：malicious-utils',
            'content': '''检测发现：malicious-utils

风险等级：medium
置信度：87.5%

详细分析：
这个PyPI包声称提供实用工具函数，但包含恶意代码，会在安装时执行系统命令并收集系统信息。

恶意行为：
1. 在setup.py中执行系统命令
2. 收集主机名、用户名等系统信息
3. 尝试建立网络连接
4. 隐藏真实的恶意功能

技术细节：
- 使用base64编码隐藏恶意代码
- 在安装过程中执行命令
- 伪装成正常的工具包

防护建议：
1. 使用虚拟环境安装包
2. 检查setup.py文件内容
3. 监控网络连接和系统调用
4. 使用安全扫描工具
5. 定期更新依赖包''',
            'package_name': 'malicious-utils',
            'package_type': 'pypi',
            'risk_level': 'medium',
            'confidence': 87.5
        },
        {
            'title': '如何识别供应链攻击中的恶意包',
            'content': '''供应链攻击是当前最严重的安全威胁之一，恶意包是其主要载体。以下是一些识别技巧：

1. 包名检查
- 检查是否有拼写错误或相似名称
- 注意包名的合理性
- 避免使用新注册的相似包名

2. 发布者信息
- 查看发布者的注册时间
- 检查发布者的其他项目
- 注意发布者的活跃度

3. 代码审查
- 查看源代码（如果有）
- 检查依赖关系
- 注意可疑的网络请求

4. 社区反馈
- 查看下载量和评分
- 阅读用户评论
- 关注安全公告

5. 工具辅助
- 使用安全扫描工具
- 配置依赖检查
- 定期更新依赖

记住：安全永远是第一位的，宁可多花时间检查，也不要冒险使用可疑的包。''',
            'package_name': None,
            'package_type': None,
            'risk_level': None,
            'confidence': None
        }
    ]
    
    for post_data in sample_posts:
        CommunityPost.create_post(
            user_id=test_user.id,
            title=post_data['title'],
            content=post_data['content'],
            package_name=post_data['package_name'],
            package_type=post_data['package_type'],
            risk_level=post_data['risk_level'],
            confidence=post_data['confidence']
        )

if __name__ == '__main__':
    init_community_database() 