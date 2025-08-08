 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSQDS系统数据初始化脚本
"""

from app import app, db, DataObject, SecurityEvent, SecurityRule, ThreatDatabase, WeightConfig

def init_database():
    """初始化数据库"""
    print("🚀 初始化DSQDS系统数据库...")
    
    with app.app_context():
        # 创建所有表
        db.create_all()
        
        # 检查是否已有数据
        if DataObject.query.first() or SecurityRule.query.first():
            print("⚠️  数据库已有数据，跳过初始化")
            return
        
        print("📝 添加初始数据...")
        
        # 初始化默认权重配置
        default_weights = [
            WeightConfig(indicator_name='S', weight=0.2, calculation_method='空间尺度归一化'),
            WeightConfig(indicator_name='P', weight=0.2, calculation_method='位置精度归一化'),
            WeightConfig(indicator_name='C', weight=0.3, calculation_method='内容敏感性评估'),
            WeightConfig(indicator_name='F', weight=0.15, calculation_method='数据流通性分析'),
            WeightConfig(indicator_name='H', weight=0.15, calculation_method='历史风险统计')
        ]
        for weight in default_weights:
            db.session.add(weight)
        
        # 初始化威胁数据库
        default_threats = [
            ThreatDatabase(threat_id='T001', stage='采集', threat_type='非法设备入侵', description='未授权设备接入数据采集网络', impact_scope='数据完整性', risk_level=0.7),
            ThreatDatabase(threat_id='T002', stage='采集', threat_type='数据篡改', description='采集过程中数据被恶意修改', impact_scope='数据完整性', risk_level=0.8),
            ThreatDatabase(threat_id='T003', stage='采集', threat_type='采集误差', description='传感器故障或环境干扰导致数据误差', impact_scope='数据真实性', risk_level=0.5),
            ThreatDatabase(threat_id='T004', stage='传输', threat_type='数据包截获', description='传输过程中数据包被截获', impact_scope='数据机密性', risk_level=0.6),
            ThreatDatabase(threat_id='T005', stage='传输', threat_type='链路监听', description='网络链路被恶意监听', impact_scope='数据机密性', risk_level=0.7),
            ThreatDatabase(threat_id='T006', stage='传输', threat_type='注入攻击', description='传输过程中遭受SQL注入等攻击', impact_scope='数据可用性', risk_level=0.8),
            ThreatDatabase(threat_id='T007', stage='存储', threat_type='权限配置漏洞', description='存储系统存在权限管理漏洞', impact_scope='访问控制', risk_level=0.7),
            ThreatDatabase(threat_id='T008', stage='存储', threat_type='介质损坏', description='存储介质物理损坏导致数据丢失', impact_scope='数据可用性', risk_level=0.6),
            ThreatDatabase(threat_id='T009', stage='存储', threat_type='物理盗窃', description='存储设备被物理盗窃', impact_scope='数据保密性', risk_level=0.9),
            ThreatDatabase(threat_id='T010', stage='共享', threat_type='越权访问', description='用户超出权限范围访问数据', impact_scope='访问控制', risk_level=0.8),
            ThreatDatabase(threat_id='T011', stage='共享', threat_type='敏感数据无控制扩散', description='敏感数据在共享过程中失控扩散', impact_scope='数据可控性', risk_level=0.8),
            ThreatDatabase(threat_id='T012', stage='应用', threat_type='非法调用', description='应用程序非法调用数据接口', impact_scope='数据完整性', risk_level=0.7),
            ThreatDatabase(threat_id='T013', stage='应用', threat_type='数据滥用', description='应用程序非法使用数据', impact_scope='数据使用', risk_level=0.6),
            ThreatDatabase(threat_id='T014', stage='应用', threat_type='内容泄漏', description='应用过程中敏感内容被泄漏', impact_scope='数据追溯性', risk_level=0.8)
        ]
        for threat in default_threats:
            db.session.add(threat)
        
        # 初始化数据对象
        default_data_objects = [
            DataObject(
                name='国家重点工程遥感影像数据',
                data_type='遥感影像',
                spatial_scale=1.0,  # 国家级
                position_accuracy=1.0,  # 厘米级
                content_sensitivity=1.0,  # 涉敏重
                data_flow=0.8,  # 频繁共享
                historical_risk=0.0,  # 无历史泄露
                lifecycle_stage='存储',
                security_score=0.92,
                security_level='核心数据'
            ),
            DataObject(
                name='省级基础地理信息数据',
                data_type='基础地理信息',
                spatial_scale=0.8,  # 省级
                position_accuracy=0.8,  # 分米级
                content_sensitivity=0.5,  # 一般
                data_flow=0.6,  # 偶尔共享
                historical_risk=0.0,  # 无历史泄露
                lifecycle_stage='共享',
                security_score=0.68,
                security_level='重要数据'
            ),
            DataObject(
                name='市级专题地图数据',
                data_type='专题地图',
                spatial_scale=0.6,  # 市级
                position_accuracy=0.6,  # 米级
                content_sensitivity=0.3,  # 普通
                data_flow=0.4,  # 偶尔共享
                historical_risk=0.2,  # 曾有轻微泄露
                lifecycle_stage='应用',
                security_score=0.48,
                security_level='一般数据'
            ),
            DataObject(
                name='县级公开地理数据',
                data_type='公开地理数据',
                spatial_scale=0.4,  # 县级
                position_accuracy=0.4,  # 米级以下
                content_sensitivity=0.0,  # 普通
                data_flow=0.2,  # 封闭
                historical_risk=0.0,  # 无历史泄露
                lifecycle_stage='应用',
                security_score=0.24,
                security_level='公开数据'
            ),
            DataObject(
                name='传感器实时监测数据',
                data_type='传感器数据',
                spatial_scale=0.7,  # 省级
                position_accuracy=0.9,  # 厘米级
                content_sensitivity=0.7,  # 涉敏
                data_flow=0.9,  # 频繁流转
                historical_risk=0.1,  # 轻微历史风险
                lifecycle_stage='传输',
                security_score=0.76,
                security_level='重要数据'
            )
        ]
        for data_obj in default_data_objects:
            db.session.add(data_obj)
        
        # 初始化安全事件
        default_security_events = [
            SecurityEvent(
                event_id='E001',
                data_object_id=1,
                trigger_condition='检测到异常访问行为',
                executed_strategy='启动多因子认证，提升数据分级',
                result='成功阻止未授权访问，数据分级从重要数据提升为核心数据'
            ),
            SecurityEvent(
                event_id='E002',
                data_object_id=2,
                trigger_condition='外部安全预警触发',
                executed_strategy='限制数据共享，启动审计记录',
                result='有效控制数据流通，记录完整操作日志'
            ),
            SecurityEvent(
                event_id='E003',
                data_object_id=3,
                trigger_condition='检测到数据多次流转未脱敏',
                executed_strategy='强制脱敏处理，限制共享次数',
                result='数据成功脱敏，共享次数限制生效'
            ),
            SecurityEvent(
                event_id='E004',
                data_object_id=4,
                trigger_condition='存储介质异常检测',
                executed_strategy='数据只读锁定，触发安全审计',
                result='及时发现并修复存储问题，数据安全得到保障'
            ),
            SecurityEvent(
                event_id='E005',
                data_object_id=5,
                trigger_condition='权限配置错误检测',
                executed_strategy='重新配置访问权限，通知管理员',
                result='权限配置已修正，系统安全性得到提升'
            )
        ]
        for event in default_security_events:
            db.session.add(event)
        
        # 初始化安全规则（扩展版）
        default_rules = [
            SecurityRule(
                rule_id='R001', 
                condition_type='属性规则',
                condition_json='{"type": "score_threshold", "threshold": 0.8}',
                action_json='{"type": "encryption", "level": "high", "description": "高级加密存储"}',
                priority=1
            ),
            SecurityRule(
                rule_id='R002',
                condition_type='属性规则', 
                condition_json='{"type": "security_level", "level": "核心数据"}',
                action_json='{"type": "access_control", "level": "strict", "description": "严格访问控制"}',
                priority=2
            ),
            SecurityRule(
                rule_id='R003',
                condition_type='环节规则',
                condition_json='{"type": "lifecycle_stage", "stage": "共享"}',
                action_json='{"type": "audit", "level": "full", "description": "全程审计记录"}',
                priority=1
            ),
            SecurityRule(
                rule_id='R004',
                condition_type='事件触发规则',
                condition_json='{"type": "external_threat", "threat_level": "high"}',
                action_json='{"type": "level_upgrade", "description": "数据分级提升一级，启动多因子认证"}',
                priority=1
            ),
            SecurityRule(
                rule_id='R005',
                condition_type='复合规则',
                condition_json='{"type": "composite", "conditions": [{"type": "data_type", "value": "遥感影像"}, {"type": "position_accuracy", "threshold": 0.9}]}',
                action_json='{"type": "core_classification", "description": "分级为核心数据，加密存储，访问权限最小化"}',
                priority=1
            ),
            SecurityRule(
                rule_id='R006',
                condition_type='环节规则',
                condition_json='{"type": "lifecycle_stage", "stage": "传输"}',
                action_json='{"type": "encrypted_transmission", "description": "全过程加密传输"}',
                priority=2
            ),
            SecurityRule(
                rule_id='R007',
                condition_type='属性规则',
                condition_json='{"type": "historical_risk", "threshold": 0.5}',
                action_json='{"type": "enhanced_monitoring", "description": "审核频次提升，分级门槛上调"}',
                priority=2
            ),
            SecurityRule(
                rule_id='R008',
                condition_type='事件触发规则',
                condition_json='{"type": "data_flow_anomaly", "frequency": "high"}',
                action_json='{"type": "flow_control", "description": "限制共享次数，强制脱敏处理"}',
                priority=1
            ),
            SecurityRule(
                rule_id='R009',
                condition_type='环节规则',
                condition_json='{"type": "lifecycle_stage", "stage": "存储"}',
                action_json='{"type": "storage_protection", "description": "数据只读锁定，触发系统安全审计"}',
                priority=2
            ),
            SecurityRule(
                rule_id='R010',
                condition_type='复合规则',
                condition_json='{"type": "composite", "conditions": [{"type": "content_sensitivity", "threshold": 0.8}, {"type": "spatial_scale", "threshold": 0.9}]}',
                action_json='{"type": "military_grade", "description": "军事级加密，全流程监控，多因子审批"}',
                priority=1
            )
        ]
        for rule in default_rules:
            db.session.add(rule)
        
        # 提交所有数据
        db.session.commit()
        
        print("✅ 数据库初始化完成！")
        print(f"📊 数据对象: {DataObject.query.count()} 条")
        print(f"🔔 安全事件: {SecurityEvent.query.count()} 条")
        print(f"⚙️  安全规则: {SecurityRule.query.count()} 条")
        print(f"⚠️  威胁数据: {ThreatDatabase.query.count()} 条")
        print(f"⚖️  权重配置: {WeightConfig.query.count()} 条")
        print("\n💡 现在可以启动系统: python app.py")

if __name__ == '__main__':
    init_database()