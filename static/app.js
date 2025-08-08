// 全局变量
let charts = {};
let currentData = {};

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    loadDashboard();
    loadDataObjects();
    loadThreats();
    loadWeights();
    loadRules();
    loadEvents();
});

// 显示指定的内容区域
function showSection(sectionId) {
    // 隐藏所有内容区域
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // 移除所有导航链接的活跃状态
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // 显示目标区域
    document.getElementById(sectionId).classList.add('active');
    
    // 设置对应导航链接为活跃状态
    event.target.classList.add('active');
    
    // 根据不同区域加载相应数据
    switch(sectionId) {
        case 'dashboard':
            refreshDashboard();
            break;
        case 'data-objects':
            loadDataObjects();
            break;
        case 'threats':
            loadThreats();
            break;
        case 'weights':
            loadWeights();
            break;
        case 'rules':
            loadRules();
            break;
        case 'events':
            loadEvents();
            break;
    }
}

// API请求封装
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API请求错误:', error);
        showAlert('请求失败: ' + error.message, 'danger');
        throw error;
    }
}

// 显示警告消息
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.top = '20px';
    alertDiv.style.right = '20px';
    alertDiv.style.zIndex = '9999';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // 3秒后自动消失
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.parentNode.removeChild(alertDiv);
        }
    }, 3000);
}

// 仪表板相关函数
async function loadDashboard() {
    try {
        const data = await apiRequest('/api/analytics/dashboard');
        currentData.dashboard = data;
        
        // 更新关键指标
        document.getElementById('total-objects').textContent = data.total_data_objects;
        document.getElementById('total-threats').textContent = data.total_threats;
        document.getElementById('total-rules').textContent = data.total_rules;
        
        // 创建图表
        createSecurityLevelChart(data.security_level_distribution);
        createLifecycleChart(data.lifecycle_stage_distribution);
        createThreatChart(data.threat_statistics);
        
        // 显示最近事件
        displayRecentEvents(data.recent_events);
        
    } catch (error) {
        console.error('加载仪表板数据失败:', error);
    }
}

function refreshDashboard() {
    document.querySelector('#dashboard').classList.add('loading');
    loadDashboard().finally(() => {
        document.querySelector('#dashboard').classList.remove('loading');
    });
}

// 创建安全等级分布图表
function createSecurityLevelChart(data) {
    const ctx = document.getElementById('security-level-chart').getContext('2d');
    
    if (charts.securityLevel) {
        charts.securityLevel.destroy();
    }
    
    charts.securityLevel = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(item => item.level),
            datasets: [{
                data: data.map(item => item.count),
                backgroundColor: [
                    '#dc3545', // 核心数据
                    '#fd7e14', // 重要数据
                    '#ffc107', // 一般数据
                    '#198754'  // 公开数据
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// 创建生命周期阶段图表
function createLifecycleChart(data) {
    const ctx = document.getElementById('lifecycle-chart').getContext('2d');
    
    if (charts.lifecycle) {
        charts.lifecycle.destroy();
    }
    
    charts.lifecycle = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(item => item.stage),
            datasets: [{
                label: '数据对象数量',
                data: data.map(item => item.count),
                backgroundColor: 'rgba(102, 126, 234, 0.6)',
                borderColor: 'rgba(102, 126, 234, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// 创建威胁统计图表
function createThreatChart(data) {
    const ctx = document.getElementById('threat-chart').getContext('2d');
    
    if (charts.threat) {
        charts.threat.destroy();
    }
    
    charts.threat = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(item => item.stage),
            datasets: [{
                label: '威胁数量',
                data: data.map(item => item.count),
                backgroundColor: 'rgba(220, 53, 69, 0.6)',
                borderColor: 'rgba(220, 53, 69, 1)',
                borderWidth: 1
            }, {
                label: '平均风险等级',
                data: data.map(item => item.avg_risk),
                type: 'line',
                borderColor: 'rgba(255, 193, 7, 1)',
                backgroundColor: 'rgba(255, 193, 7, 0.2)',
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    position: 'left'
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    min: 0,
                    max: 1,
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

// 显示最近事件
function displayRecentEvents(events) {
    const container = document.getElementById('recent-events-list');
    
    if (events.length === 0) {
        container.innerHTML = '<p class="text-muted">暂无安全事件</p>';
        return;
    }
    
    container.innerHTML = events.map(event => `
        <div class="border-start border-primary ps-3 mb-3">
            <div class="small text-muted">${formatDateTime(event.event_time)}</div>
            <div class="fw-bold">${event.trigger_condition}</div>
            <div class="small">${event.result}</div>
        </div>
    `).join('');
}

// 数据对象管理相关函数
async function loadDataObjects() {
    try {
        const data = await apiRequest('/api/data-objects');
        displayDataObjects(data);
    } catch (error) {
        console.error('加载数据对象失败:', error);
    }
}

function displayDataObjects(objects) {
    const tbody = document.getElementById('objects-table-body');
    
    if (objects.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">暂无数据对象</td></tr>';
        return;
    }
    
    tbody.innerHTML = objects.map(obj => `
        <tr>
            <td>${obj.name}</td>
            <td>${obj.data_type}</td>
            <td><span class="stage-badge stage-${obj.lifecycle_stage}">${obj.lifecycle_stage}</span></td>
            <td>
                <div class="d-flex align-items-center">
                    <div class="progress me-2" style="width: 100px; height: 8px;">
                        <div class="progress-bar" style="width: ${obj.security_score * 100}%"></div>
                    </div>
                    <span>${obj.security_score.toFixed(2)}</span>
                </div>
            </td>
            <td><span class="security-level level-${obj.security_level}">${obj.security_level}</span></td>
            <td>${formatDateTime(obj.updated_at)}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary me-1" onclick="editDataObject(${obj.id})">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteDataObject(${obj.id})">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

// 添加数据对象
async function addDataObject() {
    const form = document.getElementById('addObjectForm');
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);
    
    try {
        const result = await apiRequest('/api/data-objects', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        showAlert('数据对象添加成功', 'success');
        bootstrap.Modal.getInstance(document.getElementById('addObjectModal')).hide();
        form.reset();
        loadDataObjects();
        
        // 显示执行的安全规则
        if (result.executed_actions && result.executed_actions.length > 0) {
            showAlert(`安全规则已执行: ${result.executed_actions.length} 条规则`, 'info');
        }
        
    } catch (error) {
        showAlert('添加失败: ' + error.message, 'danger');
    }
}

// 删除数据对象
async function deleteDataObject(id) {
    if (!confirm('确定要删除这个数据对象吗？')) {
        return;
    }
    
    try {
        await apiRequest(`/api/data-objects/${id}`, {
            method: 'DELETE'
        });
        
        showAlert('数据对象删除成功', 'success');
        loadDataObjects();
    } catch (error) {
        showAlert('删除失败: ' + error.message, 'danger');
    }
}

// 威胁管理相关函数
async function loadThreats() {
    try {
        const stage = document.getElementById('threat-stage-filter')?.value || '';
        const url = stage ? `/api/threats?stage=${encodeURIComponent(stage)}` : '/api/threats';
        const data = await apiRequest(url);
        displayThreats(data);
    } catch (error) {
        console.error('加载威胁数据失败:', error);
    }
}

function displayThreats(threats) {
    const container = document.getElementById('threats-list');
    
    if (threats.length === 0) {
        container.innerHTML = '<p class="text-muted">暂无威胁数据</p>';
        return;
    }
    
    container.innerHTML = threats.map(threat => `
        <div class="threat-item">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">${threat.threat_type}</h6>
                    <span class="stage-badge stage-${threat.stage}">${threat.stage}</span>
                    <span class="badge bg-warning">${threat.threat_id}</span>
                </div>
                <div class="text-end">
                    <div class="small text-muted">风险等级</div>
                    <div class="fw-bold text-danger">${threat.risk_level.toFixed(1)}</div>
                </div>
            </div>
            <p class="mb-1 mt-2">${threat.description}</p>
            <div class="small text-muted">影响范围: ${threat.impact_scope}</div>
        </div>
    `).join('');
}

// 权重配置相关函数
async function loadWeights() {
    try {
        const data = await apiRequest('/api/weights');
        displayWeights(data);
    } catch (error) {
        console.error('加载权重配置失败:', error);
    }
}

function displayWeights(weights) {
    const container = document.getElementById('weights-config');
    
    const indicators = {
        'S': '空间尺度',
        'P': '位置精度', 
        'C': '内容敏感性',
        'F': '数据流通性',
        'H': '历史风险'
    };
    
    container.innerHTML = weights.map(weight => `
        <div class="row mb-3">
            <div class="col-md-3">
                <label class="form-label fw-bold">${indicators[weight.indicator_name]} (${weight.indicator_name})</label>
            </div>
            <div class="col-md-6">
                <input type="range" class="form-range" id="weight-${weight.indicator_name}" 
                       min="0" max="1" step="0.05" value="${weight.weight}"
                       oninput="updateWeightValue('${weight.indicator_name}', this.value)">
            </div>
            <div class="col-md-2">
                <input type="number" class="form-control" id="weight-value-${weight.indicator_name}" 
                       min="0" max="1" step="0.05" value="${weight.weight}"
                       onchange="updateWeightSlider('${weight.indicator_name}', this.value)">
            </div>
            <div class="col-md-1">
                <span class="text-muted small">${(weight.weight * 100).toFixed(0)}%</span>
            </div>
        </div>
        <div class="row mb-4">
            <div class="col-md-12">
                <small class="text-muted">${weight.calculation_method}</small>
            </div>
        </div>
    `).join('');
}

function updateWeightValue(indicator, value) {
    document.getElementById(`weight-value-${indicator}`).value = value;
    document.querySelector(`#weight-${indicator}`).nextElementSibling.textContent = (value * 100).toFixed(0) + '%';
}

function updateWeightSlider(indicator, value) {
    document.getElementById(`weight-${indicator}`).value = value;
    document.querySelector(`#weight-${indicator}`).nextElementSibling.textContent = (value * 100).toFixed(0) + '%';
}

async function saveWeights() {
    const weights = [];
    const indicators = ['S', 'P', 'C', 'F', 'H'];
    
    for (const indicator of indicators) {
        const value = parseFloat(document.getElementById(`weight-value-${indicator}`).value);
        weights.push({
            indicator_name: indicator,
            weight: value
        });
    }
    
    // 检查权重总和
    const total = weights.reduce((sum, w) => sum + w.weight, 0);
    if (Math.abs(total - 1.0) > 0.01) {
        showAlert(`权重总和应为1.0，当前为${total.toFixed(2)}`, 'warning');
        return;
    }
    
    try {
        await apiRequest('/api/weights', {
            method: 'PUT',
            body: JSON.stringify(weights)
        });
        
        showAlert('权重配置保存成功', 'success');
    } catch (error) {
        showAlert('保存失败: ' + error.message, 'danger');
    }
}

// 安全规则相关函数
async function loadRules() {
    try {
        const data = await apiRequest('/api/rules');
        displayRules(data);
    } catch (error) {
        console.error('加载安全规则失败:', error);
    }
}

function displayRules(rules) {
    const container = document.getElementById('rules-list');
    
    if (rules.length === 0) {
        container.innerHTML = '<p class="text-muted">暂无安全规则</p>';
        return;
    }
    
    container.innerHTML = rules.map(rule => `
        <div class="rule-item">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">${rule.rule_id}</h6>
                    <span class="badge bg-secondary">${rule.condition_type}</span>
                    <span class="badge ${rule.is_active ? 'bg-success' : 'bg-danger'}">${rule.is_active ? '启用' : '禁用'}</span>
                </div>
                <div class="text-end">
                    <div class="small text-muted">优先级</div>
                    <div class="fw-bold">${rule.priority}</div>
                </div>
            </div>
            <div class="mt-2">
                <div class="row">
                    <div class="col-md-6">
                        <small class="text-muted">条件:</small>
                        <pre class="small bg-light p-2 rounded">${formatJSON(rule.condition_json)}</pre>
                    </div>
                    <div class="col-md-6">
                        <small class="text-muted">动作:</small>
                        <pre class="small bg-light p-2 rounded">${formatJSON(rule.action_json)}</pre>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

// 安全事件相关函数
async function loadEvents() {
    try {
        const data = await apiRequest('/api/events');
        displayEvents(data);
    } catch (error) {
        console.error('加载安全事件失败:', error);
    }
}

function displayEvents(events) {
    const tbody = document.getElementById('events-table-body');
    
    if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">暂无安全事件</td></tr>';
        return;
    }
    
    tbody.innerHTML = events.map(event => `
        <tr>
            <td><code>${event.event_id.substring(0, 8)}</code></td>
            <td>${event.trigger_condition}</td>
            <td><small>${event.executed_strategy}</small></td>
            <td><span class="badge bg-success">${event.result}</span></td>
            <td>${formatDateTime(event.event_time)}</td>
        </tr>
    `).join('');
}

// 批量评估相关函数
async function performBatchAssessment() {
    const input = document.getElementById('batch-data').value.trim();
    
    if (!input) {
        showAlert('请输入评估数据', 'warning');
        return;
    }
    
    try {
        const dataObjects = JSON.parse(input);
        
        if (!Array.isArray(dataObjects)) {
            throw new Error('输入数据应为数组格式');
        }
        
        const result = await apiRequest('/api/batch-assessment', {
            method: 'POST',
            body: JSON.stringify({ data_objects: dataObjects })
        });
        
        displayBatchResults(result);
        showAlert(result.message, 'success');
        
    } catch (error) {
        if (error instanceof SyntaxError) {
            showAlert('JSON格式错误: ' + error.message, 'danger');
        } else {
            showAlert('评估失败: ' + error.message, 'danger');
        }
    }
}

function displayBatchResults(result) {
    const container = document.getElementById('batch-results');
    
    if (!result.results || result.results.length === 0) {
        container.innerHTML = '';
        return;
    }
    
    container.innerHTML = `
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">批量评估结果</h6>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>对象名称</th>
                                <th>安全分值</th>
                                <th>安全等级</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${result.results.map(item => `
                                <tr>
                                    <td>${item.name}</td>
                                    <td>
                                        <div class="d-flex align-items-center">
                                            <div class="progress me-2" style="width: 80px; height: 6px;">
                                                <div class="progress-bar" style="width: ${item.security_score * 100}%"></div>
                                            </div>
                                            <span class="small">${item.security_score.toFixed(2)}</span>
                                        </div>
                                    </td>
                                    <td><span class="security-level level-${item.security_level}">${item.security_level}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

// 工具函数
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('zh-CN');
}

function formatJSON(jsonString) {
    try {
        const obj = JSON.parse(jsonString);
        return JSON.stringify(obj, null, 2);
    } catch (e) {
        return jsonString;
    }
}

function updateRangeValue(slider, targetId) {
    document.getElementById(targetId).textContent = slider.value;
}