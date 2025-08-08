# DSQDS 部署指南

## 快速启动

### 方法1：使用启动脚本（推荐）
```bash
python run.py
```

### 方法2：直接启动
```bash
python app.py
```

## 系统验证

### 启动后验证
1. 系统启动后会自动打开浏览器
2. 访问 http://localhost:3000
3. 检查仪表板是否正常显示

### 功能测试
```bash
python test_system.py
```

## 目录结构
```
DSQDS/
├── app.py                 # 主应用文件
├── api_routes.py          # API路由定义
├── run.py                 # 启动脚本
├── test_system.py         # 测试脚本
├── requirements.txt       # Python依赖
├── README.md             # 项目说明
├── DEPLOYMENT.md         # 部署指南
├── static/               # 静态文件目录
│   ├── index.html        # 主页面
│   └── app.js           # 前端JavaScript
└── dsqds.db             # SQLite数据库（首次运行时创建）
```

## 核心功能验证清单

### ✅ 基础功能
- [ ] 系统正常启动
- [ ] Web界面加载正常
- [ ] 数据库自动创建
- [ ] 初始数据加载完成

### ✅ 数据对象管理
- [ ] 添加数据对象
- [ ] 查看对象列表
- [ ] 安全分值自动计算
- [ ] 安全等级自动分级
- [ ] 对象更新和删除

### ✅ 多维量化评估
- [ ] 空间尺度 (S) 评估
- [ ] 位置精度 (P) 评估
- [ ] 内容敏感性 (C) 评估
- [ ] 数据流通性 (F) 评估
- [ ] 历史风险 (H) 评估
- [ ] 权重配置功能

### ✅ 动态分级决策
- [ ] 四级分级（核心/重要/一般/公开）
- [ ] 实时分级调整
- [ ] 生命周期阶段影响
- [ ] 外部威胁响应

### ✅ 威胁管理
- [ ] 威胁清单查看
- [ ] 按阶段筛选威胁
- [ ] 威胁风险评估
- [ ] 威胁信息展示

### ✅ 安全规则引擎
- [ ] 规则自动执行
- [ ] 条件匹配逻辑
- [ ] 策略动作触发
- [ ] 规则优先级处理

### ✅ 可视化分析
- [ ] 仪表板数据展示
- [ ] 安全等级分布图
- [ ] 生命周期阶段统计
- [ ] 威胁统计图表
- [ ] 实时事件日志

### ✅ 批量处理
- [ ] 批量数据导入
- [ ] 批量安全评估
- [ ] 结果批量导出

## 系统配置

### 默认配置
- **服务端口**: 5000
- **数据库**: SQLite (dsqds.db)
- **调试模式**: 开启 (开发环境)

### 权重配置
```python
默认权重分配：
- 空间尺度 (S): 20%
- 位置精度 (P): 20% 
- 内容敏感性 (C): 30%
- 数据流通性 (F): 15%
- 历史风险 (H): 15%
```

### 分级阈值
```python
安全等级划分：
- 核心数据: score >= 0.8
- 重要数据: 0.6 <= score < 0.8
- 一般数据: 0.3 <= score < 0.6
- 公开数据: score < 0.3
```

## 生产环境部署

### 1. 环境配置
```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate     # Windows

# 安装依赖
pip install -r requirements.txt
```

### 2. 数据库配置
```python
# 生产环境建议使用PostgreSQL或MySQL
# 修改app.py中的数据库URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/dsqds'
```

### 3. Web服务器配置
```bash
# 使用Gunicorn部署（Linux）
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# 或使用waitress（跨平台）
pip install waitress
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

### 4. 反向代理配置（Nginx示例）
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /static {
        alias /path/to/DSQDS/static;
    }
}
```

## 安全建议

### 1. 数据保护
- 定期备份数据库文件
- 启用数据库加密
- 配置访问权限控制

### 2. 网络安全
- 使用HTTPS加密传输
- 配置防火墙规则
- 启用访问日志记录

### 3. 应用安全
- 关闭调试模式
- 设置安全的Session密钥
- 实施输入验证和过滤

## 监控和维护

### 1. 日志监控
- 应用日志：Flask应用日志
- 访问日志：Web服务器访问日志
- 安全事件：系统安全事件日志

### 2. 性能监控
- 数据库性能
- API响应时间
- 系统资源使用率

### 3. 定期维护
- 数据库优化
- 日志文件清理
- 系统安全更新

## 故障排除

### 常见问题

1. **端口占用**
   ```bash
   # 检查端口使用情况
   netstat -ano | findstr :5000
   # 或使用其他端口启动
   python app.py  # 修改代码中的端口号
   ```

2. **依赖安装失败**
   ```bash
   # 升级pip
   python -m pip install --upgrade pip
   # 使用国内镜像
   pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/
   ```

3. **数据库连接问题**
   - 检查SQLite文件权限
   - 确认数据库路径正确
   - 查看应用启动日志

4. **前端页面无法加载**
   - 检查static目录是否存在
   - 确认静态文件路径配置
   - 查看浏览器控制台错误

## 技术支持

如遇到部署问题，可以：
1. 查看应用启动日志
2. 运行测试脚本验证功能
3. 检查系统环境和依赖版本
4. 参考README.md中的详细说明

祝您使用愉快！🎉