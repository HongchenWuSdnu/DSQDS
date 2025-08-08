from flask import request, jsonify
from app import app, db, DataObject, ThreatDatabase, WeightConfig, SecurityRule, SecurityEvent
from app import SecurityQuantificationEngine, DynamicClassificationEngine, SecurityRuleEngine
from datetime import datetime
import uuid

# API路由定义

@app.route('/')
def index():
    """主页"""
    return app.send_static_file('index.html')

@app.route('/api/data-objects', methods=['GET', 'POST'])
def handle_data_objects():
    """数据对象管理"""
    if request.method == 'GET':
        objects = DataObject.query.all()
        return jsonify([{
            'id': obj.id,
            'name': obj.name,
            'data_type': obj.data_type,
            'spatial_scale': obj.spatial_scale,
            'position_accuracy': obj.position_accuracy,
            'content_sensitivity': obj.content_sensitivity,
            'data_flow': obj.data_flow,
            'historical_risk': obj.historical_risk,
            'lifecycle_stage': obj.lifecycle_stage,
            'security_score': obj.security_score,
            'security_level': obj.security_level,
            'created_at': obj.created_at.isoformat(),
            'updated_at': obj.updated_at.isoformat()
        } for obj in objects])
    
    elif request.method == 'POST':
        data = request.json
        
        # 创建新的数据对象
        obj = DataObject(
            name=data['name'],
            data_type=data['data_type'],
            spatial_scale=float(data.get('spatial_scale', 0)),
            position_accuracy=float(data.get('position_accuracy', 0)),
            content_sensitivity=float(data.get('content_sensitivity', 0)),
            data_flow=float(data.get('data_flow', 0)),
            historical_risk=float(data.get('historical_risk', 0)),
            lifecycle_stage=data.get('lifecycle_stage', '采集')
        )
        
        # 计算安全分值和等级
        obj.security_score = SecurityQuantificationEngine.calculate_security_score(
            obj.spatial_scale, obj.position_accuracy, obj.content_sensitivity,
            obj.data_flow, obj.historical_risk
        )
        obj.security_level = SecurityQuantificationEngine.determine_security_level(obj.security_score)
        
        db.session.add(obj)
        db.session.commit()
        
        # 执行安全规则
        actions = SecurityRuleEngine.execute_rules(obj)
        
        # 记录安全事件
        if actions:
            event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                data_object_id=obj.id,
                trigger_condition=f"新建数据对象: {obj.name}",
                executed_strategy=str(actions),
                result="规则执行成功"
            )
            db.session.add(event)
            db.session.commit()
        
        return jsonify({
            'message': '数据对象创建成功',
            'id': obj.id,
            'security_score': obj.security_score,
            'security_level': obj.security_level,
            'executed_actions': actions
        })

@app.route('/api/data-objects/<int:obj_id>', methods=['PUT', 'DELETE'])
def handle_data_object(obj_id):
    """单个数据对象操作"""
    obj = DataObject.query.get_or_404(obj_id)
    
    if request.method == 'PUT':
        data = request.json
        
        # 更新属性
        obj.name = data.get('name', obj.name)
        obj.data_type = data.get('data_type', obj.data_type)
        obj.spatial_scale = float(data.get('spatial_scale', obj.spatial_scale))
        obj.position_accuracy = float(data.get('position_accuracy', obj.position_accuracy))
        obj.content_sensitivity = float(data.get('content_sensitivity', obj.content_sensitivity))
        obj.data_flow = float(data.get('data_flow', obj.data_flow))
        obj.historical_risk = float(data.get('historical_risk', obj.historical_risk))
        obj.lifecycle_stage = data.get('lifecycle_stage', obj.lifecycle_stage)
        obj.updated_at = datetime.utcnow()
        
        # 重新计算安全分值
        old_score = obj.security_score
        obj.security_score = SecurityQuantificationEngine.calculate_security_score(
            obj.spatial_scale, obj.position_accuracy, obj.content_sensitivity,
            obj.data_flow, obj.historical_risk
        )
        
        # 动态分级调整
        external_threats = request.json.get('external_threats', [])
        if external_threats:
            obj.security_score = DynamicClassificationEngine.adjust_classification(obj, external_threats)
        
        obj.security_level = SecurityQuantificationEngine.determine_security_level(obj.security_score)
        
        db.session.commit()
        
        # 如果分级发生变化，执行相应规则
        actions = []
        if abs(old_score - obj.security_score) > 0.1:  # 分值变化超过0.1
            actions = SecurityRuleEngine.execute_rules(obj)
            
            # 记录分级变更事件
            event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                data_object_id=obj.id,
                trigger_condition=f"分级调整: {old_score:.2f} → {obj.security_score:.2f}",
                executed_strategy=str(actions),
                result="动态分级成功"
            )
            db.session.add(event)
            db.session.commit()
        
        return jsonify({
            'message': '数据对象更新成功',
            'security_score': obj.security_score,
            'security_level': obj.security_level,
            'score_change': obj.security_score - old_score,
            'executed_actions': actions
        })
    
    elif request.method == 'DELETE':
        db.session.delete(obj)
        db.session.commit()
        return jsonify({'message': '数据对象删除成功'})

@app.route('/api/threats', methods=['GET', 'POST'])
def handle_threats():
    """威胁管理"""
    if request.method == 'GET':
        stage = request.args.get('stage')
        query = ThreatDatabase.query
        if stage:
            query = query.filter_by(stage=stage)
        
        threats = query.all()
        return jsonify([{
            'id': threat.id,
            'threat_id': threat.threat_id,
            'stage': threat.stage,
            'threat_type': threat.threat_type,
            'description': threat.description,
            'impact_scope': threat.impact_scope,
            'risk_level': threat.risk_level,
            'created_at': threat.created_at.isoformat()
        } for threat in threats])
    
    elif request.method == 'POST':
        data = request.json
        threat = ThreatDatabase(
            threat_id=data['threat_id'],
            stage=data['stage'],
            threat_type=data['threat_type'],
            description=data.get('description', ''),
            impact_scope=data.get('impact_scope', ''),
            risk_level=float(data.get('risk_level', 0.5))
        )
        db.session.add(threat)
        db.session.commit()
        
        return jsonify({'message': '威胁添加成功', 'id': threat.id})

@app.route('/api/weights', methods=['GET', 'PUT'])
def handle_weights():
    """权重配置管理"""
    if request.method == 'GET':
        weights = WeightConfig.query.all()
        return jsonify([{
            'id': weight.id,
            'indicator_name': weight.indicator_name,
            'weight': weight.weight,
            'calculation_method': weight.calculation_method,
            'updated_at': weight.updated_at.isoformat()
        } for weight in weights])
    
    elif request.method == 'PUT':
        data = request.json
        for item in data:
            weight_config = WeightConfig.query.filter_by(indicator_name=item['indicator_name']).first()
            if weight_config:
                weight_config.weight = float(item['weight'])
                weight_config.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'message': '权重配置更新成功'})

@app.route('/api/rules', methods=['GET', 'POST'])
def handle_rules():
    """安全规则管理"""
    if request.method == 'GET':
        rules = SecurityRule.query.all()
        return jsonify([{
            'id': rule.id,
            'rule_id': rule.rule_id,
            'condition_type': rule.condition_type,
            'condition_json': rule.condition_json,
            'action_json': rule.action_json,
            'priority': rule.priority,
            'is_active': rule.is_active,
            'created_at': rule.created_at.isoformat()
        } for rule in rules])
    
    elif request.method == 'POST':
        data = request.json
        rule = SecurityRule(
            rule_id=data['rule_id'],
            condition_type=data['condition_type'],
            condition_json=data['condition_json'],
            action_json=data['action_json'],
            priority=int(data.get('priority', 1)),
            is_active=data.get('is_active', True)
        )
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({'message': '安全规则添加成功', 'id': rule.id})

@app.route('/api/events', methods=['GET'])
def get_events():
    """获取安全事件"""
    events = SecurityEvent.query.order_by(SecurityEvent.event_time.desc()).limit(100).all()
    return jsonify([{
        'id': event.id,
        'event_id': event.event_id,
        'data_object_id': event.data_object_id,
        'trigger_condition': event.trigger_condition,
        'executed_strategy': event.executed_strategy,
        'result': event.result,
        'event_time': event.event_time.isoformat()
    } for event in events])

@app.route('/api/analytics/dashboard', methods=['GET'])
def get_dashboard_data():
    """获取仪表板数据"""
    # 安全等级分布
    level_stats = db.session.query(
        DataObject.security_level,
        db.func.count(DataObject.id).label('count')
    ).group_by(DataObject.security_level).all()
    
    # 生命周期阶段分布
    stage_stats = db.session.query(
        DataObject.lifecycle_stage,
        db.func.count(DataObject.id).label('count')
    ).group_by(DataObject.lifecycle_stage).all()
    
    # 威胁统计
    threat_stats = db.session.query(
        ThreatDatabase.stage,
        db.func.count(ThreatDatabase.id).label('count'),
        db.func.avg(ThreatDatabase.risk_level).label('avg_risk')
    ).group_by(ThreatDatabase.stage).all()
    
    # 最近安全事件
    recent_events = SecurityEvent.query.order_by(SecurityEvent.event_time.desc()).limit(5).all()
    
    return jsonify({
        'security_level_distribution': [{'level': item[0], 'count': item[1]} for item in level_stats],
        'lifecycle_stage_distribution': [{'stage': item[0], 'count': item[1]} for item in stage_stats],
        'threat_statistics': [{'stage': item[0], 'count': item[1], 'avg_risk': float(item[2] or 0)} for item in threat_stats],
        'recent_events': [{
            'event_id': event.event_id,
            'trigger_condition': event.trigger_condition,
            'result': event.result,
            'event_time': event.event_time.isoformat()
        } for event in recent_events],
        'total_data_objects': DataObject.query.count(),
        'total_threats': ThreatDatabase.query.count(),
        'total_rules': SecurityRule.query.filter_by(is_active=True).count()
    })

@app.route('/api/batch-assessment', methods=['POST'])
def batch_assessment():
    """批量安全评估"""
    data = request.json
    results = []
    
    for item in data.get('data_objects', []):
        # 计算安全分值
        score = SecurityQuantificationEngine.calculate_security_score(
            float(item.get('spatial_scale', 0)),
            float(item.get('position_accuracy', 0)),
            float(item.get('content_sensitivity', 0)),
            float(item.get('data_flow', 0)),
            float(item.get('historical_risk', 0))
        )
        
        level = SecurityQuantificationEngine.determine_security_level(score)
        
        results.append({
            'name': item.get('name'),
            'security_score': score,
            'security_level': level
        })
    
    return jsonify({
        'message': f'批量评估完成，共处理 {len(results)} 个对象',
        'results': results
    })