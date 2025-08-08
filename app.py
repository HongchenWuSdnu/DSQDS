from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import numpy as np
import json
import os

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dsqds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)

db = SQLAlchemy(app)

# 数据模型
class DataObject(db.Model):
    """数据对象表"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    data_type = db.Column(db.String(100), nullable=False)
    spatial_scale = db.Column(db.Float, default=0.0)  # S - 空间尺度 [0,1]
    position_accuracy = db.Column(db.Float, default=0.0)  # P - 位置精度 [0,1]
    content_sensitivity = db.Column(db.Float, default=0.0)  # C - 内容敏感性 [0,1]
    data_flow = db.Column(db.Float, default=0.0)  # F - 数据流通性 [0,1]
    historical_risk = db.Column(db.Float, default=0.0)  # H - 历史风险 [0,1]
    lifecycle_stage = db.Column(db.String(50), default='采集')  # 生命周期阶段
    security_score = db.Column(db.Float, default=0.0)  # 安全分值
    security_level = db.Column(db.String(20), default='一般数据')  # 安全等级
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThreatDatabase(db.Model):
    """威胁清单表"""
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.String(50), unique=True, nullable=False)
    stage = db.Column(db.String(20), nullable=False)  # 采集/传输/存储/共享/应用
    threat_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    impact_scope = db.Column(db.String(100))
    risk_level = db.Column(db.Float, default=0.5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class WeightConfig(db.Model):
    """指标权重表"""
    id = db.Column(db.Integer, primary_key=True)
    indicator_name = db.Column(db.String(50), nullable=False)  # S/P/C/F/H
    weight = db.Column(db.Float, nullable=False, default=0.2)
    calculation_method = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SecurityRule(db.Model):
    """安全规则库表"""
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(50), unique=True, nullable=False)
    condition_type = db.Column(db.String(50), nullable=False)  # 属性规则/环节规则/事件触发规则/复合规则
    condition_json = db.Column(db.Text, nullable=False)  # JSON格式的条件
    action_json = db.Column(db.Text, nullable=False)  # JSON格式的动作
    priority = db.Column(db.Integer, default=1)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecurityEvent(db.Model):
    """安全事件表"""
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(50), unique=True, nullable=False)
    data_object_id = db.Column(db.Integer, db.ForeignKey('data_object.id'))
    trigger_condition = db.Column(db.Text)
    executed_strategy = db.Column(db.Text)
    result = db.Column(db.Text)
    event_time = db.Column(db.DateTime, default=datetime.utcnow)

# 多维安全属性量化算法
class SecurityQuantificationEngine:
    @staticmethod
    def calculate_security_score(spatial_scale, position_accuracy, content_sensitivity, data_flow, historical_risk):
        """计算安全分值"""
        # 获取权重配置
        weights = {}
        weight_configs = WeightConfig.query.all()
        for config in weight_configs:
            weights[config.indicator_name] = config.weight
        
        # 默认权重（如果数据库中没有配置）
        if not weights:
            weights = {'S': 0.2, 'P': 0.2, 'C': 0.3, 'F': 0.15, 'H': 0.15}
        
        # 计算加权分值
        score = (
            weights.get('S', 0.2) * spatial_scale +
            weights.get('P', 0.2) * position_accuracy +
            weights.get('C', 0.3) * content_sensitivity +
            weights.get('F', 0.15) * data_flow +
            weights.get('H', 0.15) * historical_risk
        )
        
        return min(max(score, 0.0), 1.0)  # 确保在[0,1]范围内
    
    @staticmethod
    def determine_security_level(score):
        """根据分值确定安全等级"""
        if score >= 0.8:
            return '核心数据'
        elif score >= 0.6:
            return '重要数据'
        elif score >= 0.3:
            return '一般数据'
        else:
            return '公开数据'

# 动态分级决策引擎
class DynamicClassificationEngine:
    @staticmethod
    def adjust_classification(data_object, external_threats=None):
        """动态调整数据分级"""
        base_score = data_object.security_score
        adjusted_score = base_score
        
        # 根据外部威胁调整
        if external_threats:
            threat_adjustment = sum([threat.get('impact', 0) for threat in external_threats])
            adjusted_score = min(base_score + threat_adjustment, 1.0)
        
        # 根据生命周期阶段调整
        stage_multipliers = {
            '采集': 1.0,
            '传输': 1.1,
            '存储': 1.05,
            '共享': 1.2,
            '应用': 1.15
        }
        
        multiplier = stage_multipliers.get(data_object.lifecycle_stage, 1.0)
        adjusted_score = min(adjusted_score * multiplier, 1.0)
        
        return adjusted_score

# 安全规则引擎
class SecurityRuleEngine:
    @staticmethod
    def execute_rules(data_object):
        """执行安全规则"""
        executed_actions = []
        rules = SecurityRule.query.filter_by(is_active=True).order_by(SecurityRule.priority.desc()).all()
        
        for rule in rules:
            try:
                condition = json.loads(rule.condition_json)
                if SecurityRuleEngine._check_condition(data_object, condition):
                    action = json.loads(rule.action_json)
                    executed_actions.append({
                        'rule_id': rule.rule_id,
                        'action': action
                    })
            except Exception as e:
                print(f"规则执行错误: {e}")
        
        return executed_actions
    
    @staticmethod
    def _check_condition(data_object, condition):
        """检查条件是否满足"""
        condition_type = condition.get('type')
        
        if condition_type == 'score_threshold':
            return data_object.security_score >= condition.get('threshold', 0)
        elif condition_type == 'security_level':
            return data_object.security_level == condition.get('level')
        elif condition_type == 'lifecycle_stage':
            return data_object.lifecycle_stage == condition.get('stage')
        
        return False

# 导入API路由
import api_routes

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 初始化默认权重配置
        if not WeightConfig.query.first():
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
            
            db.session.commit()
    
    print("DSQDS系统启动成功！")
    print("访问地址: http://localhost:3000")
    print("系统功能包括:")
    print("- 多维安全属性量化评估")
    print("- 动态分级决策")
    print("- 威胁清单管理")
    print("- 安全规则引擎")
    print("- 闭环防护机制")
    
    app.run(debug=True, host='0.0.0.0', port=3000)