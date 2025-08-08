#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSQDS系统启动脚本
全生命周期自然资源多维安全量化与动态分级体系
"""

import os
import sys
import subprocess
import webbrowser
import time
from threading import Timer

def check_dependencies():
    """检查依赖是否安装"""
    try:
        import flask
        import flask_sqlalchemy
        import flask_cors
        import numpy
        import requests
        print("✓ 所有依赖已安装")
        return True
    except ImportError as e:
        print(f"✗ 缺少依赖: {e}")
        print("请运行: pip install -r requirements.txt")
        return False

def open_browser():
    """延迟打开浏览器"""
    time.sleep(2)
    try:
        webbrowser.open('http://localhost:3000')
        print("🌐 已自动打开浏览器")
    except:
        print("🌐 请手动访问: http://localhost:3000")

def main():
    """主函数"""
    print("=" * 60)
    print("🛡️  DSQDS - 全生命周期自然资源多维安全量化与动态分级体系")
    print("=" * 60)
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    print("\n🚀 启动系统...")
    print("📊 功能模块:")
    print("   - 多维安全属性量化评估")
    print("   - 动态分级决策引擎")
    print("   - 威胁清单管理")
    print("   - 安全规则引擎")
    print("   - 闭环防护机制")
    print("   - 可视化分析界面")
    
    # 设置自动打开浏览器
    Timer(3.0, open_browser).start()
    
    try:
        # 启动Flask应用
        from app import app, db
        print(f"\n✓ 系统启动成功!")
        print(f"🔗 访问地址: http://localhost:3000")
        print(f"📱 移动端访问: http://你的IP地址:3000")
        print(f"⏹️  停止服务: Ctrl+C")
        print("-" * 60)
        
        # 确保数据库目录存在
        os.makedirs(os.path.dirname(os.path.abspath('dsqds.db')), exist_ok=True)
        
        with app.app_context():
            db.create_all()
        
        app.run(
            debug=False,  # 生产环境关闭debug
            host='0.0.0.0',
            port=3000,
            threaded=True
        )
        
    except KeyboardInterrupt:
        print("\n\n👋 系统已停止")
    except Exception as e:
        print(f"\n❌ 启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()