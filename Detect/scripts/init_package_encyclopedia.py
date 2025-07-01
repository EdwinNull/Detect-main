#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
包百科数据初始化脚本
用于向数据库中添加一些常见的开源组件包信息
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.models.db_models import PackageEncyclopedia

def init_package_encyclopedia():
    """初始化包百科数据"""
    
    # 主流PyPI和npm包百科内容
    sample_packages = [
        # PyPI
        {
            'package_name': 'requests',
            'package_type': 'Python',
            'description': '最流行的 Python HTTP 库，简化了 HTTP 请求的发送和响应处理。',
            'version': '2.31.0',
            'author': 'Kenneth Reitz',
            'license': 'Apache 2.0',
            'repository': 'https://github.com/psf/requests',
            'official_website': 'https://docs.python-requests.org/',
            'tags': '网络请求,HTTP客户端,API,Web',
            'security_notes': '支持 HTTPS 和证书验证，注意不要禁用 SSL 验证。',
            'common_risks': 'SSRF、信息泄露、证书验证绕过、未设置超时。',
            'best_practices': '验证用户输入、启用 SSL 验证、设置超时、定期更新。',
            'alternatives': 'httpx, urllib3, aiohttp, httplib2'
        },
        {
            'package_name': 'pandas',
            'package_type': 'Python',
            'description': '强大的数据分析和处理库，提供灵活的数据结构和高效的数据操作工具。',
            'version': '2.2.2',
            'author': 'Wes McKinney',
            'license': 'BSD',
            'repository': 'https://github.com/pandas-dev/pandas',
            'official_website': 'https://pandas.pydata.org/',
            'tags': '数据分析,数据处理,ETL,DataFrame',
            'security_notes': '大数据集操作时注意内存和性能。',
            'common_risks': '链式赋值、内存溢出。',
            'best_practices': '使用内置方法、避免 for 循环处理数据。',
            'alternatives': 'dask, modin, polars'
        },
        {
            'package_name': 'Django',
            'package_type': 'Python',
            'description': '高级 Python Web 框架，鼓励快速开发和简洁、实用的设计。',
            'version': '5.0.4',
            'author': 'Django Software Foundation',
            'license': 'BSD',
            'repository': 'https://github.com/django/django',
            'official_website': 'https://www.djangoproject.com/',
            'tags': 'Web框架,后端,ORM,安全',
            'security_notes': '内置多种安全防护（如CSRF、XSS、SQL注入防护），但需定期升级。',
            'common_risks': '配置不当导致安全机制失效。',
            'best_practices': '使用官方推荐配置、定期升级、关闭debug。',
            'alternatives': 'flask, fastapi, tornado'
        },
        {
            'package_name': 'matplotlib',
            'package_type': 'Python',
            'description': '最常用的 Python 绘图库，支持多种图表类型和自定义。',
            'version': '3.8.4',
            'author': 'John D. Hunter et al.',
            'license': 'PSF',
            'repository': 'https://github.com/matplotlib/matplotlib',
            'official_website': 'https://matplotlib.org/',
            'tags': '可视化,绘图,科学计算',
            'security_notes': '注意图片输出路径权限。',
            'common_risks': '大数据绘图时内存消耗大。',
            'best_practices': '分批绘图、及时关闭figure。',
            'alternatives': 'seaborn, plotly, bokeh'
        },
        {
            'package_name': 'scikit-learn',
            'package_type': 'Python',
            'description': '机器学习领域最流行的 Python 库，支持分类、回归、聚类等多种算法。',
            'version': '1.4.2',
            'author': 'scikit-learn developers',
            'license': 'BSD',
            'repository': 'https://github.com/scikit-learn/scikit-learn',
            'official_website': 'https://scikit-learn.org/',
            'tags': '机器学习,数据挖掘,算法',
            'security_notes': '注意数据泄露风险，避免训练集和测试集混用。',
            'common_risks': '特征泄露、过拟合。',
            'best_practices': '使用交叉验证、标准化数据、合理选择模型。',
            'alternatives': 'xgboost, lightgbm, tensorflow'
        },
        # npm
        {
            'package_name': 'express',
            'package_type': 'JavaScript',
            'description': '最流行的 Node.js Web 框架，极简且灵活，支持中间件机制。',
            'version': '4.18.2',
            'author': 'TJ Holowaychuk',
            'license': 'MIT',
            'repository': 'https://github.com/expressjs/express',
            'official_website': 'https://expressjs.com/',
            'tags': 'Web框架,Node.js,后端,API',
            'security_notes': '需配合 Helmet、CORS 等安全中间件。',
            'common_risks': '路由未做权限校验、未处理异常、依赖包安全问题。',
            'best_practices': '使用安全中间件、统一错误处理、定期升级依赖。',
            'alternatives': 'koa, fastify, nestjs, hapi'
        },
        {
            'package_name': 'react',
            'package_type': 'JavaScript',
            'description': '由 Facebook 推出的前端 UI 框架，组件化开发，虚拟 DOM。',
            'version': '18.2.0',
            'author': 'Facebook',
            'license': 'MIT',
            'repository': 'https://github.com/facebook/react',
            'official_website': 'https://react.dev/',
            'tags': '前端,UI,组件化,单页应用',
            'security_notes': '注意 XSS 风险，避免使用 dangerouslySetInnerHTML。',
            'common_risks': 'XSS、依赖包漏洞、状态管理混乱。',
            'best_practices': '使用受控组件、定期升级依赖。',
            'alternatives': 'vue, angular, preact'
        },
        {
            'package_name': 'lodash',
            'package_type': 'JavaScript',
            'description': '功能丰富的 JavaScript 工具库，提供常用数据处理函数。',
            'version': '4.17.21',
            'author': 'John-David Dalton',
            'license': 'MIT',
            'repository': 'https://github.com/lodash/lodash',
            'official_website': 'https://lodash.com/',
            'tags': '工具库,数据处理,函数式编程,高性能',
            'security_notes': '注意原型污染风险，定期升级。',
            'common_risks': '原型污染、滥用导致包体积膨胀。',
            'best_practices': '只引入需要的函数、定期升级。',
            'alternatives': 'underscore, ramda, immer'
        },
        {
            'package_name': 'axios',
            'package_type': 'JavaScript',
            'description': '基于 Promise 的 HTTP 客户端，支持浏览器和 Node.js。',
            'version': '1.6.8',
            'author': 'Matt Zabriskie',
            'license': 'MIT',
            'repository': 'https://github.com/axios/axios',
            'official_website': 'https://axios-http.com/',
            'tags': 'HTTP,API,前后端通信,Promise',
            'security_notes': '需设置超时，注意 XSS 风险。',
            'common_risks': '未处理超时、未做错误处理、XSS 风险。',
            'best_practices': '统一封装请求、设置超时、处理异常。',
            'alternatives': 'fetch, superagent, got'
        },
        {
            'package_name': 'vue',
            'package_type': 'JavaScript',
            'description': '渐进式 JavaScript 框架，专注于构建用户界面，易于集成。',
            'version': '3.4.21',
            'author': '尤雨溪等',
            'license': 'MIT',
            'repository': 'https://github.com/vuejs/vue',
            'official_website': 'https://vuejs.org/',
            'tags': '前端,UI,组件化,响应式',
            'security_notes': '注意 XSS 风险，避免直接操作 DOM。',
            'common_risks': 'XSS、依赖包漏洞。',
            'best_practices': '使用受控组件、定期升级依赖。',
            'alternatives': 'react, angular, svelte'
        },
        {
            'package_name': 'moment',
            'package_type': 'JavaScript',
            'description': '流行的 JavaScript 日期处理库，API 简单易用。',
            'version': '2.30.1',
            'author': 'Iskren Ivov Chernev',
            'license': 'MIT',
            'repository': 'https://github.com/moment/moment',
            'official_website': 'https://momentjs.com/',
            'tags': '日期处理,时间,工具库',
            'security_notes': '注意时区处理，官方已不再维护，建议迁移。',
            'common_risks': '时区混乱、包体积大。',
            'best_practices': '优先使用 dayjs、date-fns 等替代品。',
            'alternatives': 'dayjs, date-fns, luxon'
        }
    ]
    print("开始初始化包百科数据...")
    for package_data in sample_packages:
        try:
            package = PackageEncyclopedia(**package_data)
            package.save()
            print(f"✓ 已添加: {package.package_name}")
        except Exception as e:
            print(f"✗ 添加失败 {package_data['package_name']}: {str(e)}")
    print("包百科数据初始化完成！")
    all_packages = PackageEncyclopedia.get_all()
    print(f"\n当前包百科条目总数: {len(all_packages)}")
    type_count = {}
    for pkg in all_packages:
        type_count[pkg.package_type] = type_count.get(pkg.package_type, 0) + 1
    print("按类型统计:")
    for pkg_type, count in type_count.items():
        print(f"  {pkg_type}: {count} 个")

if __name__ == '__main__':
    init_package_encyclopedia() 