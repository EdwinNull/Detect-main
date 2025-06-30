from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import subprocess
import os
import sys

@admin_bp.route('/crawl_packages', methods=['GET', 'POST'])
@admin_required
def crawl_packages():
    result = None
    if request.method == 'POST':
        pkg_type = request.form.get('pkg_type', 'npm')
        limit = request.form.get('limit', 5)
        try:
            limit = int(limit)
        except Exception:
            limit = 5
        # 构造命令
        script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'package_crawler.py')
        if pkg_type not in ['npm', 'pypi']:
            pkg_type = 'npm'
        cmd = [sys.executable, script_path, pkg_type, str(limit)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            result = proc.stdout + '\n' + proc.stderr
        except Exception as e:
            result = f'抓取失败: {e}'
    return render_template('crawl_packages.html', result=result) 