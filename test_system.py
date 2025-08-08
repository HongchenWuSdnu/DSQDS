#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSQDS系统功能测试脚本
"""

import requests
import json
import time

BASE_URL = "http://localhost:3000"

def test_api_endpoint(method, endpoint, data=None, description=""):
    """测试API端点"""
    try:
        url = f"{BASE_URL}{endpoint}"
        
        if method.upper() == "GET":
            response = requests.get(url)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers={'Content-Type': 'application/json'})
        elif method.upper() == "PUT":
            response = requests.put(url, json=data, headers={'Content-Type': 'application/json'})
        else:
            return False, f"不支持的HTTP方法: {method}"
        
        if response.status_code in [200, 201]:
            return True, response.json()
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except requests.exceptions.ConnectionError:
        return False, "连接失败，请确保服务器正在运行"
    except Exception as e:
        return False, str(e)

def run_tests():
    """运行系统测试"""
    print("🧪 DSQDS系统功能测试")
    print("=" * 50)
    
    tests = [
        {
            "name": "获取仪表板数据",
            "method": "GET",
            "endpoint": "/api/analytics/dashboard",
            "data": None
        },
        {
            "name": "添加测试数据对象",
            "method": "POST", 
            "endpoint": "/api/data-objects",
            "data": {
                "name": "测试地理数据",
                "data_type": "地理数据",
                "spatial_scale": 0.8,
                "position_accuracy": 0.7,
                "content_sensitivity": 0.9,
                "data_flow": 0.4,
                "historical_risk": 0.3,
                "lifecycle_stage": "采集"
            }
        },
        {
            "name": "获取数据对象列表",
            "method": "GET",
            "endpoint": "/api/data-objects",
            "data": None
        },
        {
            "name": "获取威胁清单",
            "method": "GET", 
            "endpoint": "/api/threats",
            "data": None
        },
        {
            "name": "获取权重配置",
            "method": "GET",
            "endpoint": "/api/weights", 
            "data": None
        },
        {
            "name": "获取安全规则",
            "method": "GET",
            "endpoint": "/api/rules",
            "data": None
        },
        {
            "name": "获取安全事件",
            "method": "GET",
            "endpoint": "/api/events",
            "data": None
        },
        {
            "name": "批量安全评估",
            "method": "POST",
            "endpoint": "/api/batch-assessment",
            "data": {
                "data_objects": [
                    {
                        "name": "批量测试数据1",
                        "spatial_scale": 0.6,
                        "position_accuracy": 0.5,
                        "content_sensitivity": 0.8,
                        "data_flow": 0.3,
                        "historical_risk": 0.4
                    },
                    {
                        "name": "批量测试数据2", 
                        "spatial_scale": 0.9,
                        "position_accuracy": 0.8,
                        "content_sensitivity": 0.7,
                        "data_flow": 0.2,
                        "historical_risk": 0.5
                    }
                ]
            }
        }
    ]
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(tests, 1):
        print(f"\n{i}. {test['name']}")
        print("-" * 30)
        
        success, result = test_api_endpoint(
            test['method'],
            test['endpoint'], 
            test['data']
        )
        
        if success:
            print("✅ 通过")
            if isinstance(result, dict):
                # 显示关键信息
                if 'message' in result:
                    print(f"   消息: {result['message']}")
                if 'security_score' in result:
                    print(f"   安全分值: {result['security_score']:.2f}")
                if 'security_level' in result:
                    print(f"   安全等级: {result['security_level']}")
                if 'total_data_objects' in result:
                    print(f"   数据对象总数: {result['total_data_objects']}")
                if 'results' in result and isinstance(result['results'], list):
                    print(f"   处理结果数: {len(result['results'])}")
            passed += 1
        else:
            print(f"❌ 失败: {result}")
            failed += 1
        
        time.sleep(0.5)  # 避免请求过快
    
    print(f"\n{'='*50}")
    print(f"📊 测试结果统计:")
    print(f"   ✅ 通过: {passed}")
    print(f"   ❌ 失败: {failed}")
    print(f"   📈 成功率: {passed/(passed+failed)*100:.1f}%")
    
    if failed == 0:
        print(f"\n🎉 所有测试通过！系统运行正常。")
    else:
        print(f"\n⚠️  有 {failed} 个测试失败，请检查系统状态。")

def test_quantification_algorithm():
    """测试量化算法"""
    print(f"\n🔬 量化算法测试")
    print("-" * 30)
    
    test_cases = [
        {
            "name": "高风险数据",
            "params": {"spatial_scale": 0.9, "position_accuracy": 0.8, "content_sensitivity": 0.9, "data_flow": 0.7, "historical_risk": 0.8}
        },
        {
            "name": "中等风险数据", 
            "params": {"spatial_scale": 0.5, "position_accuracy": 0.6, "content_sensitivity": 0.6, "data_flow": 0.4, "historical_risk": 0.3}
        },
        {
            "name": "低风险数据",
            "params": {"spatial_scale": 0.2, "position_accuracy": 0.3, "content_sensitivity": 0.2, "data_flow": 0.1, "historical_risk": 0.1}
        }
    ]
    
    for case in test_cases:
        print(f"\n测试用例: {case['name']}")
        
        # 使用默认权重计算预期分值
        weights = {"S": 0.2, "P": 0.2, "C": 0.3, "F": 0.15, "H": 0.15}
        params = case['params']
        
        expected_score = (
            weights['S'] * params['spatial_scale'] +
            weights['P'] * params['position_accuracy'] + 
            weights['C'] * params['content_sensitivity'] +
            weights['F'] * params['data_flow'] +
            weights['H'] * params['historical_risk']
        )
        
        # 确定预期等级
        if expected_score >= 0.8:
            expected_level = "核心数据"
        elif expected_score >= 0.6:
            expected_level = "重要数据"
        elif expected_score >= 0.3:
            expected_level = "一般数据"
        else:
            expected_level = "公开数据"
        
        print(f"  输入参数: {params}")
        print(f"  预期分值: {expected_score:.3f}")
        print(f"  预期等级: {expected_level}")

if __name__ == "__main__":
    print("🎯 请确保DSQDS系统正在运行 (python app.py 或 python run.py)")
    input("按Enter键开始测试...")
    
    run_tests()
    test_quantification_algorithm()
    
    print(f"\n💡 提示:")
    print(f"   - 访问 http://localhost:3000 查看Web界面")
    print(f"   - 查看 README.md 了解更多使用说明")
    print(f"   - 检查 dsqds.db 数据库文件确认数据已保存")