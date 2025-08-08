 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSQDS系统数据检查脚本
"""

from app import app, db, DataObject, SecurityEvent, SecurityRule, ThreatDatabase, WeightConfig

def check_data():
    """检查数据库中的数据"""
    print("🔍 DSQDS系统数据检查")
    print("=" * 50)
    
    with app.app_context():
        # 检查数据对象
        data_objects = DataObject.query.all()
        print(f"📊 数据对象数量: {len(data_objects)}")
        for obj in data_objects:
            print(f"  - {obj.name} ({obj.data_type}) - 安全等级: {obj.security_level}")
        
        # 检查安全事件
        security_events = SecurityEvent.query.all()
        print(f"\n🔔 安全事件数量: {len(security_events)}")
        for event in security_events:
            print(f"  - {event.event_id}: {event.trigger_condition}")
        
        # 检查安全规则
        security_rules = SecurityRule.query.all()
        print(f"\n⚙️  安全规则数量: {len(security_rules)}")
        for rule in security_rules:
            print(f"  - {rule.rule_id}: {rule.condition_type}")
        
        # 检查威胁数据库
        threats = ThreatDatabase.query.all()
        print(f"\n⚠️  威胁数据库数量: {len(threats)}")
        for threat in threats:
            print(f"  - {threat.threat_id}: {threat.threat_type} ({threat.stage})")
        
        # 检查权重配置
        weights = WeightConfig.query.all()
        print(f"\n⚖️  权重配置数量: {len(weights)}")
        for weight in weights:
            print(f"  - {weight.indicator_name}: {weight.weight}")
        
        print("\n✅ 数据检查完成！")
        print("💡 系统已准备好运行，访问 http://localhost:3000 查看Web界面")

if __name__ == '__main__':
    check_data()