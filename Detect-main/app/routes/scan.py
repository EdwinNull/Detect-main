from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
import threading
import hashlib
import json
import sqlite3
from app.utils import login_required
from app.tasks import background_scan, scan_tasks
from config import Config
from app.utils.helpers import detect_package_type
from app.models.db_models import ScanRecord, FeatureData

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan')
@login_required
def scan():
    return render_template('scan.html')

@scan_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        file.save(file_path)
        # 计算文件哈希
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        file_size = os.path.getsize(file_path)
        # 检测包类型
        package_type = detect_package_type(file_path)
        # 创建扫描记录
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_records (user_id, filename, file_size, file_hash, scan_status, package_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], filename, file_size, file_hash, 'pending', package_type))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        # 初始化任务状态
        scan_tasks[scan_id] = {
            'status': 'pending',
            'progress': 0,
            'current_task': '开始检测'
        }
        # 启动后台扫描任务
        thread = threading.Thread(target=background_scan, args=(scan_id, file_path, session['user_id']))
        thread.daemon = True
        thread.start()
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': '文件上传成功，开始检测'
        })

@scan_bp.route('/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': '请先登录'}), 401
    
    # 从内存中获取实时状态
    if scan_id in scan_tasks:
        task_status = scan_tasks[scan_id]
    else:
        # 从数据库获取状态
        conn = sqlite3.connect(Config.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT scan_status FROM scan_records WHERE id = ? AND user_id = ?', 
                      (scan_id, session['user_id']))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            status = result[0]
            task_status = {
                'status': status,
                'progress': 100 if status == 'completed' else 0,
                'current_task': '检测完成' if status == 'completed' else '检测中'
            }
        else:
            return jsonify({'error': '扫描记录不存在'}), 404
    
    return jsonify(task_status)

@scan_bp.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    """显示扫描结果页面"""
    # 获取扫描记录
    scan_record = ScanRecord.get_by_id(scan_id)
    if not scan_record:
        flash('扫描记录不存在')
        return redirect(url_for('user.index'))
    
    # 获取特征数据
    feature_data = FeatureData.get_by_scan_id(scan_id)
    
    # 解析xgboost_result和llm_result
    xgboost_result = json.loads(scan_record.xgboost_result) if scan_record.xgboost_result else None
    llm_result = json.loads(scan_record.llm_result) if scan_record.llm_result else None
    
    # 准备数据
    scan_data = {
        'id': scan_record.id,
        'filename': scan_record.filename,
        'file_size': scan_record.file_size,
        'scan_time': scan_record.scan_time,
        'risk_level': scan_record.risk_level,
        'confidence': scan_record.confidence,
        'features': json.loads(feature_data.feature_data) if feature_data and feature_data.feature_data else {},
        'xgboost_result': {
            'prediction': xgboost_result.get('prediction', 0) if xgboost_result else 0,
            'confidence': xgboost_result.get('confidence', 0.0) if xgboost_result else 0.0,
            'risk_score': xgboost_result.get('risk_score', 0.0) if xgboost_result else 0.0,
            'risk_level': xgboost_result.get('risk_level', 'unknown') if xgboost_result else 'unknown',
            'feature_importance': xgboost_result.get('feature_importance', {}) if xgboost_result else {}
        } if xgboost_result else None,
        'llm_result': {
            'risk_level': llm_result.get('risk_level', 'unknown') if llm_result else 'unknown',
            'confidence': llm_result.get('confidence', 0.0) if llm_result else 0.0,
            'analysis': llm_result.get('analysis', '无分析结果') if llm_result else '无分析结果'
        } if llm_result else None
    }
    
    return render_template('results.html', scan_data=scan_data)

@scan_bp.route('/progress/<int:scan_id>')
@login_required
def progress(scan_id):
    return render_template('progress.html', scan_id=scan_id)

@scan_bp.route('/cancel_scan/<int:scan_id>', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查扫描记录是否存在且属于当前用户
    cursor.execute('SELECT id FROM scan_records WHERE id = ? AND user_id = ?', 
                  (scan_id, session['user_id']))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'error': '扫描记录不存在或无权操作'}), 404
    
    # 更新扫描状态为已取消
    cursor.execute('UPDATE scan_records SET scan_status = "cancelled" WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    
    # 从活动扫描任务中移除
    if scan_id in scan_tasks:
        del scan_tasks[scan_id]
    
    return jsonify({'success': True, 'message': '扫描已取消'})

@scan_bp.route('/retry_scan/<int:scan_id>', methods=['POST'])
@login_required
def retry_scan(scan_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查扫描记录是否存在且属于当前用户
    cursor.execute('SELECT id, file_hash FROM scan_records WHERE id = ? AND user_id = ?', 
                  (scan_id, session['user_id']))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'error': '扫描记录不存在或无权操作'}), 404
    
    # 更新扫描状态为待处理
    cursor.execute('UPDATE scan_records SET scan_status = "pending", risk_level = NULL, confidence = NULL, scan_result = NULL, llm_result = NULL, risk_explanation = NULL, scan_time = NULL WHERE id = ?', (scan_id,))
    conn.commit()
    
    # 查找文件路径
    file_hash = record[1]
    upload_dir = Config.UPLOAD_FOLDER
    
    # 查找可能的文件路径
    potential_files = []
    for root, dirs, files in os.walk(upload_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    current_hash = hashlib.md5(f.read()).hexdigest()
                    if current_hash == file_hash:
                        potential_files.append(file_path)
            except:
                continue
    
    conn.close()
    
    if not potential_files:
        return jsonify({'error': '找不到原始文件，无法重新检测'}), 404
    
    # 使用找到的第一个匹配文件进行重新检测
    file_path = potential_files[0]
    
    # 初始化任务状态
    scan_tasks[scan_id] = {
        'status': 'pending',
        'progress': 0,
        'current_task': '开始检测'
    }
    
    # 启动后台扫描任务
    thread = threading.Thread(target=background_scan, args=(scan_id, file_path, session['user_id']))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': '已开始重新检测'})

@scan_bp.route('/delete_record/<int:scan_id>', methods=['POST'])
@login_required
def delete_record(scan_id):
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # 检查扫描记录是否存在且属于当前用户
    cursor.execute('SELECT id, scan_status FROM scan_records WHERE id = ? AND user_id = ?', 
                  (scan_id, session['user_id']))
    record = cursor.fetchone()
    
    if not record:
        conn.close()
        return jsonify({'error': '扫描记录不存在或无权操作'}), 404
    
    # 如果扫描正在进行中，先取消扫描
    if record[1] == 'pending' and scan_id in scan_tasks:
        del scan_tasks[scan_id]
    
    # 删除扫描记录
    cursor.execute('DELETE FROM scan_records WHERE id = ?', (scan_id,))
    
    # 删除特征数据
    cursor.execute('DELETE FROM features WHERE scan_id = ?', (scan_id,))
    
    conn.commit()
    conn.close()
    
    # 删除相关报告文件
    report_paths = [
        f'static/reports/report_{scan_id}.json',
        f'static/reports/report_{scan_id}.pdf'
    ]
    
    for path in report_paths:
        if os.path.exists(path):
            try:
                os.remove(path)
            except:
                pass
    
    return jsonify({'success': True, 'message': '记录已删除'})
