#!/usr/bin/env python3
"""
测试模板渲染是否正常
"""
from app import create_app
from flask import render_template

def test_templates():
    app = create_app()
    app.config['SERVER_NAME'] = 'localhost:5000'

    with app.app_context():
        with app.test_request_context():
            try:
                # 测试主页模板
                print("测试主页模板...")
                result = render_template('user/index.html',
                                       stats={'total_scans': 0, 'malicious_count': 0, 'safe_count': 0, 'accuracy': 0},
                                       malicious_packages=[],
                                       recent_scans=[],
                                       total_malicious=0,
                                       total_scans=0,
                                       total_users=0,
                                       total_samples=0,
                                       is_admin=False,
                                       is_guest=True,
                                       latest_anomalies=[])
                print("✓ 主页模板渲染成功")

                # 测试登录模板
                print("测试登录模板...")
                result = render_template('auth/login.html')
                print("✓ 登录模板渲染成功")

                # 测试扫描模板
                print("测试扫描模板...")
                result = render_template('scan/scan.html')
                print("✓ 扫描模板渲染成功")

                # 测试指南模板
                print("测试指南模板...")
                result = render_template('user/guide.html')
                print("✓ 指南模板渲染成功")

                print("\n所有模板测试通过！")

            except Exception as e:
                print(f"模板渲染错误: {e}")
                import traceback
                traceback.print_exc()

if __name__ == '__main__':
    test_templates()
