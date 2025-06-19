import requests

class DeepSeekAnalyzer:
    def __init__(self, api_key=None):
        # 直接写入API Key
        self.api_key = api_key or "sk-4d9403ac0e0640328d254c6c6b32bcd0"
        self.api_url = get_setting('DEEPSEEK_API_URL', Config.DEEPSEEK_API_URL)

    def _parse_analysis(self, analysis_text, xgboost_result=None):
        """解析DeepSeek的分析结果，risk_level与XGBoost分数联动"""
        # 默认中风险
        risk_level = 'medium'
        # 先用大模型文本关键词判定
        if '高风险' in analysis_text or '高危' in analysis_text:
            risk_level = 'high'
        elif '低风险' in analysis_text or '安全' in analysis_text:
            risk_level = 'low'
        # 如果XGBoost分数很高，强制high
        if xgboost_result:
            risk_score = xgboost_result.get('risk_score', 0)
            confidence = xgboost_result.get('confidence', 0)
            # 只要risk_score或confidence大于0.6就high
            if risk_score >= 0.6 or confidence >= 0.8:
                risk_level = 'high'
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
        if any(word in analysis_text for word in ['明显', '确定', '肯定']):
            confidence += 0.1
        if any(word in analysis_text for word in ['可能', '或许', '建议']):
            confidence -= 0.1
        confidence = max(0.5, min(0.95, confidence))
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'analysis': analysis_text,
            'recommendation': '请参考分析报告中的建议措施'
        } 

    def analyze_package(self, filename, features, xgboost_result):
        print("[DEBUG] analyze_package 被调用")
        # 强制只用写死的API Key
        self.api_key = "sk-4d9403ac0e0640328d254c6c6b32bcd0"
        print(f"[DEBUG] DeepSeek API Key: {self.api_key}")
        print(f"[DEBUG] DeepSeek API URL: {self.api_url}")
        if not self.api_key:
            print("[DEBUG] DeepSeek API Key为空，走fallback分析")
            return self._fallback_analysis(xgboost_result)
        try:
            # 构建分析提示
            prompt = self._build_analysis_prompt(filename, features, xgboost_result)
            print(f"[DEBUG] DeepSeek Prompt: {prompt}")
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            data = {
                'model': 'deepseek-chat',
                'messages': [
                    {
                        'role': 'system',
                        'content': '你是一个专业的开源组件安全分析专家。你的任务是分析上传的开源组件包，识别其中可能存在的安全风险和恶意行为。请基于提供的特征数据进行深度分析，并给出详细的安全评估报告。'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.3,
                'max_tokens': 2048
            }
            print(f"[DEBUG] DeepSeek 请求体: {data}")
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            print(f"[DEBUG] DeepSeek API响应码: {response.status_code}")
            print(f"[DEBUG] DeepSeek API响应内容: {response.text}")
            if response.status_code == 200:
                result = response.json()
                analysis = result['choices'][0]['message']['content']
                return self._parse_analysis(analysis, xgboost_result)
            else:
                print(f"DeepSeek API错误: {response.status_code} - {response.text}")
                return self._fallback_analysis(xgboost_result)
        except Exception as e:
            print(f"DeepSeek分析错误: {e}")
            return self._fallback_analysis(xgboost_result)

    def _fallback_analysis(self, xgboost_result):
        print("[DEBUG] DeepSeek fallback 分支被调用")
        # 兜底分析文本和风险等级
        if xgboost_result.get('prediction', 0) == 1:
            analysis_text = '基于机器学习模型分析，该组件包存在安全风险。建议进一步人工审查。'
            xgboost_result = dict(xgboost_result)  # 防止原对象被修改
            xgboost_result['risk_score'] = xgboost_result.get('risk_score', 1.0)
        else:
            analysis_text = '基于机器学习模型分析，该组件包相对安全。'
            xgboost_result = dict(xgboost_result)
            xgboost_result['risk_score'] = xgboost_result.get('risk_score', 0.0)
        return self._parse_analysis(analysis_text, xgboost_result)

    def _build_analysis_prompt(self, filename, features, xgboost_result):
        prompt = (
            f"请你作为一名专业的开源组件安全分析专家，分析以下开源组件包的详细特征数据，找出其中可能存在的安全风险、恶意行为或可疑点，并说明原因：\n\n"
            f"文件名：{filename}\n"
            f"文件数量：{features.get('file_count', 'N/A')}\n"
            f"总大小：{features.get('total_size', 'N/A')} 字节\n"
            f"平均文件大小：{features.get('avg_file_size', 'N/A')} 字节\n"
            f"目录深度：{features.get('directory_depth', 'N/A')}\n"
            f"可执行文件数：{features.get('executable_files', 'N/A')}\n"
            f"脚本文件数：{features.get('script_files', 'N/A')}\n"
            f"配置文件数：{features.get('config_files', 'N/A')}\n"
            f"可疑扩展名文件数：{features.get('suspicious_extensions', 'N/A')}\n"
            f"隐藏文件数：{features.get('hidden_files', 'N/A')}\n"
            f"\nXGBoost初筛结果：\n"
            f"- 判定：{'恶意' if xgboost_result.get('prediction', 0) == 1 else '良性'}\n"
            f"- 置信度：{xgboost_result.get('confidence', 0.0) * 100:.2f}%\n"
            f"- 风险分数：{xgboost_result.get('risk_score', 0.0):.2f}\n"
            f"\n请你：\n1. 明确指出该组件包中最可疑或最有可能构成安全威胁的具体特征（如高熵、可疑文件、异常依赖等），并说明理由。\n2. 给出风险等级评估（高/中/低），并用简洁的语言总结主要恶意点或安全隐患。\n3. 针对检测到的风险，提出具体的安全建议或处置措施。\n\n请用中文回复，结构清晰，条理分明。"
        )
        return prompt 