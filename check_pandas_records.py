import sqlite3
import json

def check_pandas_records():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # 查找pandas相关的扫描记录
    cursor.execute("""
        SELECT id, filename, risk_level, confidence, scan_time, xgboost_result, llm_result
        FROM scan_records 
        WHERE filename LIKE '%pandas%' 
        ORDER BY scan_time DESC 
        LIMIT 5
    """)
    
    results = cursor.fetchall()
    print('最近的pandas扫描记录:')
    print('=' * 80)
    
    for record in results:
        scan_id, filename, risk_level, confidence, scan_time, xgboost_result, llm_result = record
        print(f'扫描ID: {scan_id}')
        print(f'文件名: {filename}')
        print(f'风险等级: {risk_level}')
        print(f'置信度: {confidence}')
        print(f'扫描时间: {scan_time}')
        
        if xgboost_result:
            try:
                xgb_data = json.loads(xgboost_result)
                print(f'XGBoost结果: 预测={xgb_data.get("prediction")}, 风险分数={xgb_data.get("risk_score")}, 风险等级={xgb_data.get("risk_level")}')
            except:
                print(f'XGBoost结果: {xgboost_result}')
        
        if llm_result:
            try:
                llm_data = json.loads(llm_result)
                print(f'LLM结果: 风险等级={llm_data.get("risk_level")}, 置信度={llm_data.get("confidence")}')
            except:
                print(f'LLM结果: {llm_result}')
        
        print('-' * 80)
    
    # 查找特征数据
    if results:
        scan_id = results[0][0]
        cursor.execute('SELECT feature_data FROM features WHERE scan_id = ?', (scan_id,))
        feature_result = cursor.fetchone()
        
        if feature_result:
            try:
                features = json.loads(feature_result[0])
                print(f'\n最新pandas包的特征数据:')
                print('=' * 80)
                
                # 显示关键特征
                key_features = [
                    'Number of Words in source code',
                    'Number of lines in source code',
                    'Number of base64 chunks in source code',
                    'Number of IP adress in source code',
                    'Number of sospicious token in source code',
                    '.py', '.pyc', '.pkl', '.pickle',
                    'plus ratio max', 'eq ratio max', 'bracket ratio max',
                    'shannon max ID source code', 'shannon max string source code'
                ]
                
                for feature in key_features:
                    if feature in features:
                        print(f'{feature}: {features[feature]}')
                
                # 显示所有非零特征
                non_zero_features = {k: v for k, v in features.items() if v != 0 and v != 0.0}
                if non_zero_features:
                    print(f'\n所有非零特征 ({len(non_zero_features)}个):')
                    for k, v in non_zero_features.items():
                        print(f'  {k}: {v}')
                
            except Exception as e:
                print(f'解析特征数据失败: {e}')
    
    conn.close()

if __name__ == '__main__':
    check_pandas_records() 