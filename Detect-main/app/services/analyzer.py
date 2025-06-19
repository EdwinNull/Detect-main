import requests
import json
import re
from config import Config
from app.utils.helpers import get_setting
from typing import Dict, Any

class DeepSeekAnalyzer:
    def __init__(self, api_key=None):
        # 优先使用config.py中的API Key
        self.api_key = api_key or Config.DEEPSEEK_API_KEY
        self.api_url = "https://api.deepseek.com/v1/chat/completions"
        print(f"[DEBUG] DeepSeekAnalyzer initialization - API Key: {self.api_key}")
        print(f"[DEBUG] DeepSeekAnalyzer initialization - API URL: {self.api_url}")
    
    def analyze_package(self, filename, features, xgboost_result):
        """分析软件包的安全性"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            prompt = self._build_analysis_prompt(filename, features, xgboost_result)
            
            data = {
                'model': 'deepseek-chat',
                'messages': [
                    {'role': 'system', 'content': 'You are a professional open source component security analysis expert.'},
                    {'role': 'user', 'content': prompt}
                ],
                'temperature': 0.3,
                'max_tokens': 2000
            }
            
            print(f"[DEBUG] about to send API request to: {self.api_url}")
            print(f"[DEBUG] headers: {headers}")
            print(f"[DEBUG] request data: {data}")
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
            print(f"[DEBUG] API response status code: {response.status_code}")
            print(f"[DEBUG] API response headers: {dict(response.headers)}")
            print(f"[DEBUG] API response content: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"[DEBUG] API returned JSON: {result}")
                
                if 'choices' in result and len(result['choices']) > 0:
                    analysis = result['choices'][0]['message']['content']
                    print(f"[DEBUG] extracted analysis content: {analysis}")
                    
                    parsed_result = self._parse_analysis(analysis, xgboost_result)
                    print(f"[DEBUG] parsed result: {parsed_result}")
                    return parsed_result
                else:
                    print(f"[DEBUG] API returned format exception: {result}")
                    return self._fallback_analysis(xgboost_result)
            else:
                print(f"[DEBUG] DeepSeek API error: {response.status_code} - {response.text}")
                return self._fallback_analysis(xgboost_result)
                
        except requests.exceptions.Timeout:
            print("[DEBUG] API request timeout")
            return self._fallback_analysis(xgboost_result)
        except requests.exceptions.RequestException as e:
            print(f"[DEBUG] API request exception: {e}")
            return self._fallback_analysis(xgboost_result)
        except Exception as e:
            print(f"[DEBUG] DeepSeek analysis exception: {e}")
            import traceback
            print(f"[DEBUG] exception stack: {traceback.format_exc()}")
            return self._fallback_analysis(xgboost_result)
    
    def _convert_markdown_to_friendly_text(self, markdown_text):
        """将markdown格式的分析结果转换为友好的中文显示格式"""
        if not markdown_text:
            return "暂无分析结果"
        
        # 移除markdown分隔符
        text = re.sub(r'^---+$', '', markdown_text, flags=re.MULTILINE)
        
        # 转换标题
        text = re.sub(r'### 🛡️ (.+)', r'🔒 \1', text)
        text = re.sub(r'#### (\d+️⃣) (.+)', r'📋 \2', text)
        
        # 转换表格为更友好的格式
        def convert_table(match):
            table_content = match.group(0)
            # 移除表格标记
            table_content = re.sub(r'\|.*\|.*\|.*\|', '', table_content)
            table_content = re.sub(r'\|-+\|', '', table_content)
            # 提取表格内容并转换为列表
            lines = [line.strip() for line in table_content.split('\n') if line.strip() and '|' in line]
            result = []
            for line in lines:
                cells = [cell.strip() for cell in line.split('|') if cell.strip()]
                if len(cells) >= 3:
                    result.append(f"• {cells[0]}: {cells[1]} - {cells[2]}")
            return '\n'.join(result) if result else "暂无具体特征数据"
        
        text = re.sub(r'\|.*\|.*\|.*\|[\s\S]*?\|.*\|.*\|.*\|', convert_table, text)
        
        # 转换其他markdown格式
        text = re.sub(r'\*\*(.+?)\*\*', r'【\1】', text)  # 粗体
        text = re.sub(r'`(.+?)`', r'「\1」', text)  # 代码
        text = re.sub(r'> (.+)', r'💡 \1', text)  # 引用
        
        # 转换列表
        text = re.sub(r'^\s*-\s+(.+)$', r'• \1', text, flags=re.MULTILINE)
        text = re.sub(r'^\s*(\d+)\.\s+(.+)$', r'\1. \2', text, flags=re.MULTILINE)
        
        # 清理多余的空行
        text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
        
        # 添加中文说明
        text = text.replace('Judgment', '判断结果')
        text = text.replace('Confidence', '置信度')
        text = text.replace('Risk score', '风险分数')
        text = text.replace('Malicious', '恶意')
        text = text.replace('Benign', '良性')
        text = text.replace('High', '高风险')
        text = text.replace('Medium', '中风险')
        text = text.replace('Low', '低风险')
        text = text.replace('Risk level', '风险等级')
        text = text.replace('Main risk points', '主要风险点')
        text = text.replace('Security suggestions', '安全建议')
        text = text.replace('Suggestion', '建议')
        text = text.replace('Note', '注意')
        text = text.replace('This report is generated automatically by AI', '本报告由AI自动生成')
        text = text.replace('please combine manual security review', '请结合人工安全审查')
        
        return text.strip()
    
    def _build_analysis_prompt(self, filename, features, xgboost_result):
        # 提取关键特征用于分析
        key_features = {
            'file_size': features.get('file_size', 'N/A'),
            'Number of Words in source code': features.get('Number of Words in source code', 'N/A'),
            'Number of lines in source code': features.get('Number of lines in source code', 'N/A'),
            'Number of base64 chunks in source code': features.get('Number of base64 chunks in source code', 'N/A'),
            'Number of IP adress in source code': features.get('Number of IP adress in source code', 'N/A'),
            'Number of sospicious token in source code': features.get('Number of sospicious token in source code', 'N/A'),
            'shannon mean ID source code': features.get('shannon mean ID source code', 'N/A'),
            'shannon max ID source code': features.get('shannon max ID source code', 'N/A'),
            'plus ratio max': features.get('plus ratio max', 'N/A'),
            'eq ratio max': features.get('eq ratio max', 'N/A'),
            'bracket ratio max': features.get('bracket ratio max', 'N/A'),
        }
        # 修复：生成特征摘要
        feature_summary = '\n'.join([f'- {k}: {v}' for k, v in key_features.items()])

        prompt = f"""
请作为专业的开源组件安全分析专家，结合下方详细特征数据，分析该包可能存在的安全风险、恶意行为或可疑点，并说明理由：

- 文件名：{filename}
- 主要特征数据（仅展示部分）：
{feature_summary}

请严格按照以下结构输出：

### 1️⃣ 恶意类型判断
- **类型**：请根据特征和分析，判断该包最可能属于哪类恶意类型（如"信息窃取"、"远程控制"、"依赖混淆"、"挖矿脚本"、"后门木马"等），如无明显恶意可写"无明显恶意"
- **理由**：请用简明中文说明判断依据，需结合特征值（如"发现大量base64编码，且存在可疑网络请求，疑似信息窃取"）

### 2️⃣ 主要可疑特征（Top 5）
| 特征名称 | 数值 | 描述/风险点 |
|---|---|---|
| 示例：熵均值 | 0.72 | 代码混淆、变量名异常 |
| ... | ... | ... |

### 3️⃣ 风险等级评估
- **风险等级**：高/中/低
- **主要风险点**：1. ... 2. ...

### 4️⃣ 安全建议
- 建议1：...
- 建议2：...

> **注意**：所有内容请用中文输出，结构化展示，便于人工复核。
"""

        # 追加结构化Markdown格式要求
        prompt += f'''
---
### 🛡️ 开源组件安全分析报告: {filename}

#### 1️⃣ XGBoost判断结果
- **判断结果**：{'恶意' if xgboost_result.get('prediction', 0) == 1 else '良性'}
- **置信度**：{xgboost_result.get('confidence', 0.0) * 100:.2f}%
- **风险分数**：{xgboost_result.get('risk_score', 0.0):.3f}

#### 2️⃣ 主要可疑特征（Top 5）
请用下表展示最可疑的5个特征：

| 特征名称 | 数值 | 描述/风险点 |
|---|---|---|
| 示例：熵均值 | 0.72 | 代码混淆、变量名异常 |
| ... | ... | ... |

#### 3️⃣ 风险等级评估
- **风险等级**：高/中/低
- **主要风险点**：
  1. ...
  2. ...

#### 4️⃣ 安全建议
- 建议1：...
- 建议2：...

#### 5️⃣ 恶意包类型判断
- 类型：请根据特征和分析，判断该包最可能属于哪类恶意类型（如"信息窃取"、"远程控制"、"依赖混淆"、"挖矿脚本"、"后门木马"等），如无明显恶意可写"无明显恶意"
- 理由：请用一句话说明判断依据

---

> **注意**：本报告由AI自动生成，请结合人工安全审查。

请严格使用Markdown分级标题（###、####）、表格、列表、加粗等结构化格式，避免输出大段无结构文本。所有内容请用中文输出。'''
        return prompt
    
    def _parse_analysis(self, analysis_text, xgboost_result=None):
        """解析DeepSeek的分析结果，risk_level与XGBoost分数联动"""
        print(f"[DEBUG] start parsing analysis text: {analysis_text[:200]}...")

        # 如果大模型返回内容为空或全是无，自动生成结构化兜底内容
        if not analysis_text or analysis_text.strip() == '' or all(x in analysis_text for x in ['类型', '未知', '无', '暂无']):
            print("[DEBUG] 大模型返回内容为空或全为无，自动生成兜底内容")
            # 兜底内容根据XGBoost结果和特征生成
            if xgboost_result:
                pred = xgboost_result.get('prediction', 0)
                conf = xgboost_result.get('confidence', 0.0)
                risk_score = xgboost_result.get('risk_score', 0.0)
                # 恶意类型
                mal_type = '高风险可疑包' if pred == 1 else '无明显恶意'
                mal_reason = '机器学习模型判定为高风险，建议人工复核' if pred == 1 else '未发现明显恶意特征，模型判定为安全'
                # 可疑特征
                features = xgboost_result.get('features', {}) if 'features' in xgboost_result else {}
                suspicious = []
                if features:
                    if features.get('Number of base64 chunks in source code', 0) > 10:
                        suspicious.append('| Base64块数量 | {} | 代码中存在大量Base64编码 |'.format(features['Number of base64 chunks in source code']))
                    if features.get('Number of sospicious token in source code', 0) > 10:
                        suspicious.append('| 可疑token数量 | {} | 代码中存在大量可疑token |'.format(features['Number of sospicious token in source code']))
                    if features.get('.py', 0) > 1000:
                        suspicious.append('| Python文件数 | {} | 代码体量巨大 |'.format(features['.py']))
                if not suspicious:
                    suspicious.append('暂无可疑特征数据')
                suspicious_md = '\n'.join(suspicious)
                # 风险等级
                risk_level = 'HIGH' if pred == 1 else 'SAFE'
                risk_points = '机器学习模型判定为高风险' if pred == 1 else '无'
                # 安全建议
                if pred == 1:
                    advice = ['- 建议人工复核', '- 建议停止使用', '- 关注官方安全公告']
                else:
                    advice = ['- 建议定期关注安全公告', '- 建议持续监控组件安全']
                advice_md = '\n'.join(advice)
                analysis_text = f"""### 恶意类型判断\n类型：{mal_type}\n理由：{mal_reason}\n\n### 主要可疑特征（Top 5）\n{suspicious_md}\n\n### 风险等级评估\n风险等级：{risk_level}\n主要风险点：{risk_points}\n\n### 安全建议\n{advice_md}\n"""
            else:
                analysis_text = """### 恶意类型判断\n类型：无明显恶意\n理由：未发现明显恶意特征，机器学习模型判定为安全。\n\n### 主要可疑特征（Top 5）\n暂无可疑特征数据\n\n### 风险等级评估\n风险等级：SAFE\n主要风险点：无\n\n### 安全建议\n- 建议定期关注安全公告\n- 建议持续监控组件安全\n"""

        # 默认中风险
        risk_level = 'medium'
        
        # 先用大模型文本关键词判定
        if 'High risk' in analysis_text or 'High danger' in analysis_text or 'Malicious' in analysis_text:
            risk_level = 'high'
        elif 'Low risk' in analysis_text or 'Safe' in analysis_text or 'Normal' in analysis_text:
            risk_level = 'low'
        
        # 如果XGBoost分数很高，强制high
        if xgboost_result:
            risk_score = xgboost_result.get('risk_score', 0)
            confidence = xgboost_result.get('confidence', 0)
            print(f"[DEBUG] XGBoost risk score: {risk_score}, confidence: {confidence}")
            
            # 只要risk_score或confidence大于0.6就high
            if risk_score >= 0.6 or confidence >= 0.8:
                risk_level = 'high'
                print(f"[DEBUG] forced to high risk based on XGBoost score")
            elif risk_score >= 0.4 or confidence >= 0.6:
                risk_level = 'medium'
            elif risk_score >= 0.2 or confidence >= 0.3:
                risk_level = 'low'
            else:
                risk_level = 'safe'
        
        # 计算置信度（基于文本长度和关键词）
        confidence = 0.7
        if len(analysis_text) > 200:
            confidence += 0.1
        if any(word in analysis_text for word in ['Obvious', 'Determined', 'Definitely', 'Malicious', 'Dangerous']):
            confidence += 0.1
        if any(word in analysis_text for word in ['Possible', 'Perhaps', 'Suggest', 'Need further']):
            confidence -= 0.1
        
        confidence = max(0.5, min(0.95, confidence))
        
        # 转换markdown为友好的中文显示格式
        friendly_analysis = self._convert_markdown_to_friendly_text(analysis_text)
        
        # 自动提取恶意包类型
        mal_type = "未知"
        mal_type_reason = ""
        
        # 尝试从不同格式中提取类型和理由
        type_patterns = [
            r'类型[：: ]*([\u4e00-\u9fa5A-Za-z0-9_\-]+)',
            r'恶意类型[：: ]*([\u4e00-\u9fa5A-Za-z0-9_\-]+)',
            r'判定类型[：: ]*([\u4e00-\u9fa5A-Za-z0-9_\-]+)'
        ]
        
        reason_patterns = [
            r'理由[：: ]*(.+?)(?=\n|$)',
            r'判断依据[：: ]*(.+?)(?=\n|$)',
            r'分析结果[：: ]*(.+?)(?=\n|$)'
        ]
        
        # 尝试所有模式直到找到匹配
        for pattern in type_patterns:
            type_match = re.search(pattern, analysis_text)
            if type_match:
                mal_type = type_match.group(1).strip()
                break
                
        for pattern in reason_patterns:
            reason_match = re.search(pattern, analysis_text)
            if reason_match:
                mal_type_reason = reason_match.group(1).strip()
                break
        
        # 提取主要可疑特征
        top_features = []
        try:
            # 尝试从表格中提取
            table_pattern = r'\|(.*?)\|(.*?)\|(.*?)\|'
            matches = re.findall(table_pattern, analysis_text)
            if matches:
                # 跳过表头
                for match in matches[1:6]:  # 只取前5个
                    name = match[0].strip()
                    value = match[1].strip()
                    desc = match[2].strip()
                    if name and value and desc and name != "特征名称":
                        top_features.append({
                            "name": name,
                            "value": value,
                            "desc": desc
                        })
        except Exception as e:
            print(f"[DEBUG] 提取可疑特征失败: {e}")
        
        # 提取安全建议
        advice_list = []
        try:
            advice_section = re.search(r'安全建议[：:](.*?)(?=###|$)', analysis_text, re.DOTALL)
            if advice_section:
                advice_text = advice_section.group(1)
                # 提取列表项
                advice_items = re.findall(r'[•\-\*]\s*(.+?)(?=\n|$)', advice_text)
                advice_list = [item.strip() for item in advice_items if item.strip()]
        except Exception as e:
            print(f"[DEBUG] 提取安全建议失败: {e}")
        
        # 提取风险点
        risk_points = ""
        try:
            risk_section = re.search(r'主要风险点[：:](.*?)(?=###|$)', analysis_text, re.DOTALL)
            if risk_section:
                risk_points = risk_section.group(1).strip()
        except Exception as e:
            print(f"[DEBUG] 提取风险点失败: {e}")

        result = {
            'risk_level': risk_level,
            'confidence': confidence,
            'analysis': friendly_analysis,  # 使用转换后的友好格式
            'raw_analysis': analysis_text,  # 保留原始markdown格式
            'type': mal_type,
            'reason': mal_type_reason,
            'top_features': top_features,
            'advice_list': advice_list,
            'risk_points': risk_points
        }
        
        print(f"[DEBUG] parsed result: {result}")
        return result
    
    def _fallback_analysis(self, xgboost_result):
        """当API调用失败时的后备分析"""
        print("[DEBUG] using fallback analysis")
        
        # 根据XGBoost结果生成分析文本
        if xgboost_result.get('prediction', 0) == 1:
            analysis_text = f"""🔒 开源组件安全分析报告

📋 XGBoost判断结果
• 判断结果：恶意
• 置信度：{xgboost_result.get('confidence', 0.0) * 100:.2f}%
• 风险分数：{xgboost_result.get('risk_score', 0.0):.3f}

📋 主要风险点
• 机器学习模型识别为高风险组件
• 建议进行进一步的人工审查以确认是否存在恶意代码或安全漏洞

📋 安全建议
• 立即停止使用该组件
• 检查已部署的应用是否受影响
• 寻找安全的替代组件
• 将该组件报告给相应的包管理平台

💡 注意：本报告由AI自动生成，请结合人工安全审查"""
            risk_level = 'high'
        else:
            analysis_text = f"""🔒 开源组件安全分析报告

📋 XGBoost判断结果
• 判断结果：良性
• 置信度：{xgboost_result.get('confidence', 0.0) * 100:.2f}%
• 风险分数：{xgboost_result.get('risk_score', 0.0):.3f}

📋 安全评估
• 机器学习模型分析显示该组件包相对安全
• 未发现明显的恶意行为或安全漏洞

📋 安全建议
• 建议定期更新到最新版本以确保安全
• 保持对组件包的持续监控
• 关注官方安全公告

💡 注意：本报告由AI自动生成，请结合人工安全审查"""
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'confidence': xgboost_result.get('confidence', 0.5),
            'analysis': analysis_text,
            'raw_analysis': analysis_text,
            'recommendation': '建议结合人工审查和定期安全更新'
        }