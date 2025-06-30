# 开源组件包安全检测平台

这是一个用于检测开源组件包安全风险的Web平台，可以识别和防范潜在的恶意开源组件包，保障软件供应链安全。

## 项目结构

```
Detect-main/
├── app/                    # 主应用目录
│   ├── __init__.py        # Flask应用工厂
│   ├── models/            # 数据模型
│   │   ├── __init__.py
│   │   ├── db_models.py   # 数据库模型
│   │   └── community_models.py  # 社区功能模型
│   ├── routes/            # 路由控制器
│   │   ├── __init__.py
│   │   ├── auth.py        # 认证相关路由
│   │   ├── admin.py       # 管理员路由
│   │   ├── scan.py        # 扫描功能路由
│   │   ├── user.py        # 用户功能路由
│   │   └── community.py   # 社区功能路由
│   ├── services/          # 业务逻辑服务
│   │   ├── __init__.py
│   │   ├── analyzer.py    # 分析服务
│   │   ├── classifier.py  # 分类服务
│   │   ├── extractor.py   # 特征提取服务
│   │   └── csv_feature_extractor.py  # CSV特征提取
│   ├── templates/         # HTML模板
│   │   ├── base.html      # 基础模板
│   │   ├── auth/          # 认证相关模板
│   │   ├── admin/         # 管理相关模板
│   │   ├── scan/          # 扫描相关模板
│   │   ├── user/          # 用户相关模板
│   │   └── community/     # 社区相关模板
│   ├── static/            # 静态资源
│   │   ├── css/           # 样式文件
│   │   ├── js/            # JavaScript文件
│   │   ├── images/        # 图片资源
│   │   └── reports/       # 生成的报告
│   ├── utils/             # 工具函数
│   │   ├── __init__.py
│   │   └── helpers.py     # 辅助函数
│   └── tasks.py           # 后台任务
├── config/                # 配置文件目录
│   ├── __init__.py
│   ├── config.py          # 主配置文件
│   └── settings.py        # 环境设置
├── models/                # 机器学习模型
│   ├── cross_language_model.pkl
│   ├── js_model.pkl
│   ├── py_model.pkl
│   └── xgboost_model.pkl
├── data/                  # 数据文件目录
│   ├── datasets/          # 数据集
│   ├── samples/           # 样本文件
│   └── vicious/           # 恶意样本
├── tests/                 # 测试文件目录
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_services.py
│   └── test_routes.py
├── scripts/               # 脚本文件目录
│   ├── init_db.py         # 数据库初始化
│   ├── train_model.py     # 模型训练
│   └── package_crawler.py # 包抓取脚本
├── docs/                  # 文档目录
│   ├── requirements/      # 需求文档
│   ├── design/           # 设计文档
│   └── api/              # API文档
├── logs/                  # 日志目录
├── temp/                  # 临时文件目录
│   ├── uploads/          # 上传文件
│   └── downloads/        # 下载文件
├── requirements.txt       # Python依赖
├── run.py                # 应用启动文件
└── README.md             # 项目说明
```

## 主要功能

- 自动检测上传的组件包是否含有恶意代码或安全漏洞
- 支持多种组件包格式（PyPI、npm、jar等）
- 详细的检测报告和风险评估
- 历史检测记录管理
- 恶意包知识库
- 社区功能

## 技术栈

- 后端: Python + Flask
- 前端: HTML, CSS, JavaScript
- 数据库: SQLite
- 机器学习: XGBoost
- 深度分析: LLM技术

## 安装与运行

### 环境要求
- Python 3.8+
- 推荐使用虚拟环境

### 安装步骤

1. 克隆仓库
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. 创建并激活虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 初始化数据库
```bash
python scripts/init_db.py
```

5. 运行应用
```bash
python run.py
```

6. 访问应用
在浏览器中打开 http://localhost:5000

## 重构说明

本项目已进行文件结构重构，主要改进包括：

1. **配置文件集中管理**：所有配置文件移至 `config/` 目录
2. **数据文件分类存储**：数据集、样本、恶意样本分别存储
3. **测试文件统一管理**：所有测试文件移至 `tests/` 目录
4. **脚本文件集中管理**：所有脚本文件移至 `scripts/` 目录
5. **文档文件整理**：所有文档移至 `docs/` 目录
6. **临时文件规范**：上传和下载文件统一管理
7. **导入路径修复**：所有文件导入路径已更新

## 使用指南

详细的使用指南可以在应用内通过点击"快速上手"按钮获取。

## 许可证

[MIT License](LICENSE)

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。 