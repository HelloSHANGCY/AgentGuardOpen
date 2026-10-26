<template>
  <section v-show="tab === 'baseline'" class="baseline-page">
    <ConsolePageHeader title="行为基线" class="baseline-page-head">

      <el-button size="small" :loading="refreshing" :disabled="busy" @click="reload"><el-icon class="btn-ic"><Refresh /></el-icon>刷新</el-button>
    </ConsolePageHeader>
    <div class="eval-controls" v-if="adminNeedsToken">
      <label>管理令牌<el-input size="small" v-model="adminToken" type="password" show-password autocomplete="off"
                aria-label="管理令牌" placeholder="AG_AGENT_ADMIN_TOKEN，仅保存在当前页面" @keyup.enter="reload" /></label>
      <el-button size="small" type="primary" :disabled="!adminToken || refreshing" @click="reload">加载</el-button>
    </div>
    <el-alert v-if="baselineError" :title="baselineError" type="error" show-icon class="my-12" @close="baselineError = ''" />
    <template v-if="baselineLoaded">
      <el-alert v-if="!baselineData.enabled" type="warning" show-icon :closable="false" class="my-12"
                title="行为基线已由服务端关闭" />
      <el-alert v-if="baselineData.load_warning" type="warning" show-icon :closable="false" class="my-12"
                title="原先启用的模型不可用，已回退到内置模型" />
      <el-alert v-if="baselineData.model_compatible === false" type="error" show-icon :closable="false" class="my-12"
                title="模型版本不兼容，异常打分已停用" />
      <div v-show="panel !== 'comparison'" class="baseline-overview">
        <section class="baseline-card baseline-active" aria-labelledby="baseline-active-title">
          <div class="baseline-card-head"><h3 id="baseline-active-title">当前模型</h3>
            <el-tag size="small" effect="plain" :type="scoring ? 'success' : 'warning'">{{ scoring ? '异常打分运行中' : '异常打分已停用' }}</el-tag></div>
          <div class="baseline-version"><strong class="mono">{{ active?.version || '—' }}</strong>
            <el-tag v-if="active" size="small" type="info" effect="plain">{{ active.score_semantics_version === 3 ? `${active.order} 阶插值` : active.version === 'builtin-legacy' ? '原始一阶内置' : active.score_semantics_version === 2 ? '证据模型 · 实验' : active.builtin ? '内置模型' : '训练模型' }}</el-tag></div>
          <dl class="baseline-stats">
            <div><dt>异常阈值</dt><dd class="mono">{{ active?.threshold ?? '—' }}</dd></div>
            <div><dt>夹具 AUC</dt><dd class="mono">{{ fmtNum(active?.meta?.auc) }}</dd></div>
            <div><dt>个性化设备</dt><dd>{{ active?.meta?.personalized_devices?.length || 0 }} <small>台</small></dd></div>
          </dl>
          <p class="baseline-note">训练数据：{{ dataText(active) }}</p>
          <p v-if="active?.meta?.personalized_devices?.length" class="baseline-note baseline-wrap">个性化：{{ active.meta.personalized_devices.join('、') }}</p>
        </section>
        <section class="baseline-card" aria-labelledby="baseline-data-title">
          <div class="baseline-card-head"><h3 id="baseline-data-title">真实行为数据</h3><span class="baseline-note">{{ devices.length }} 台设备</span></div>
          <dl class="baseline-stats baseline-data-stats">
            <div><dt>历史记录</dt><dd>{{ records.sessions || 0 }} <small>个会话</small></dd><span>{{ records.steps || 0 }} 步</span></div>
            <div><dt>当前版本已执行</dt><dd>{{ records.compatible_sessions || 0 }} <small>个会话</small></dd><span>{{ records.compatible_steps || 0 }} 步</span></div>
          </dl>
          <p class="baseline-note">{{ records.persistent ? '已落盘 · ' + kb(records.bytes || 0) : '仅内存保存，重启后清空' }}<span v-if="records.full" class="c-med"> · 容量已满，停止记录新会话</span></p>
        </section>
      </div>
      <el-tabs v-model="panel" class="baseline-tabs" aria-label="行为基线管理">
        <el-tab-pane label="数据与训练" name="training">
          <div class="baseline-workspace">
            <section class="baseline-card baseline-records" aria-labelledby="baseline-records-title">
              <div class="baseline-card-head"><h3 id="baseline-records-title"><span class="baseline-step" aria-hidden="true">1</span>选择训练数据</h3>
                <el-popconfirm v-if="records.sessions" title="清空全部真实会话记录？已训练的模型不受影响" confirm-button-text="清空" cancel-button-text="取消" @confirm="clearAll">
                  <template #reference><el-button link type="danger" size="small" :disabled="busy">清空全部记录</el-button></template>
                </el-popconfirm></div>

              <el-alert v-if="records.incompatible_records" type="warning" show-icon :closable="false" class="baseline-record-warning"
                        :title="`${records.incompatible_records} 条旧版记录不参与训练`" />
              <div class="baseline-datasets" aria-label="已登记的外部训练数据">
                <h4>外部数据集</h4>
                <p v-if="!datasets.length" class="baseline-note">暂无已登记的外部数据集</p>
                <article v-for="dataset in datasets" :key="dataset.id" class="baseline-dataset">
                  <div class="baseline-dataset-head"><strong>{{ dataset.name }}</strong><el-tag size="small" effect="plain" :type="dataset.available ? 'success' : 'warning'">{{ dataset.available ? '可训练' : '不可用' }}</el-tag></div>
                  <dl v-if="dataset.train" class="baseline-dataset-counts">
                    <div><dt>训练</dt><dd>{{ dataset.train.sessions }} 个会话 · {{ dataset.train.steps }} 步</dd></div>
                    <div><dt>固定验证</dt><dd>{{ dataset.holdout.sessions }} 个会话 · {{ dataset.holdout.steps }} 步</dd></div>
                    <div><dt>保留测试</dt><dd>{{ dataset.reserved_test.sessions }} 个会话</dd></div>
                  </dl>
                  <p v-if="dataset.reason" class="baseline-note c-med" role="status">{{ dataset.reason }}</p>
                </article>
              </div>
              <div class="baseline-selection">
                <el-checkbox :model-value="allSelected" :indeterminate="selected.length > 0 && !allSelected" :disabled="busy || !devices.length" @change="selectAll">选择全部设备</el-checkbox>
                <span v-if="selected.length">已选 {{ selected.length }} 台<el-button link size="small" type="primary" :disabled="busy" @click="selected = []">取消选择</el-button></span>
                <span v-else>全部设备</span>
              </div>
              <div class="baseline-device-table">
                <el-table :data="devices" size="small" row-key="device" :max-height="345" empty-text="暂无真实会话">
                  <el-table-column width="44"><template #default="{row}"><el-checkbox :model-value="selected.includes(row.device)" :aria-label="'选择设备 ' + row.device" :disabled="busy" @change="(checked) => selectDevice(row.device, checked)" /></template></el-table-column>
                  <el-table-column label="设备 / Agent" min-width="180"><template #default="{row}">
                    <div class="baseline-device-name"><span class="mono">{{ row.device }}</span><el-tag v-if="!row.registered" size="small" type="info" effect="plain">已吊销</el-tag></div>
                    <div class="baseline-device-meta"><span v-if="row.actor">{{ row.actor }} · </span><span v-for="agent in row.agents" :key="agent" class="baseline-agent"><AgentIcon :agent="agent" :size="20" />{{ AGENT_NAMES[agent] || agent }}</span></div>
                  </template></el-table-column>
                  <el-table-column label="历史 / 已执行" min-width="128" align="right"><template #default="{row}"><b>{{ row.sessions }} / {{ row.compatible_sessions || 0 }} 个会话</b><div class="baseline-note">{{ row.steps }} / {{ row.compatible_steps || 0 }} 步</div></template></el-table-column>
                  <el-table-column label="含拦截/确认" width="106" align="right"><template #default="{row}"><span :class="{'c-med':row.flagged}">{{ row.flagged }} 个会话</span></template></el-table-column>
                  <el-table-column label="最近活动" min-width="130"><template #default="{row}"><span :title="'首次记录：' + fmtTs(row.first)" class="baseline-note">{{ fmtTs(row.last) }}</span></template></el-table-column>
                  <el-table-column width="60" fixed="right"><template #default="{row}"><el-popconfirm :title="'清空 ' + row.device + ' 的记录？'" confirm-button-text="清空" cancel-button-text="取消" @confirm="clearDevice(row.device)"><template #reference><el-button link type="danger" size="small" :disabled="busy" :aria-label="'清空设备 ' + row.device + ' 的记录'">清空</el-button></template></el-popconfirm></template></el-table-column>
                </el-table>
              </div>
              <div class="baseline-device-cards">
                <p v-if="!devices.length" class="baseline-empty">暂无真实会话</p>
                <article v-for="row in devices" :key="row.device" class="baseline-device-card">
                  <el-checkbox :model-value="selected.includes(row.device)" :aria-label="'选择设备 ' + row.device" :disabled="busy" @change="(checked) => selectDevice(row.device, checked)"><span class="mono">{{ row.device }}</span></el-checkbox>
                  <div class="baseline-device-meta"><el-tag v-if="!row.registered" size="small" type="info" effect="plain">已吊销</el-tag><span v-if="row.actor">{{ row.actor }}</span><span v-for="agent in row.agents" :key="agent" class="baseline-agent"><AgentIcon :agent="agent" :size="20" />{{ AGENT_NAMES[agent] || agent }}</span></div>
                  <dl class="baseline-device-counts"><div><dt>历史 / 已执行会话</dt><dd>{{ row.sessions }} / {{ row.compatible_sessions || 0 }}</dd></div><div><dt>历史 / 已执行步数</dt><dd>{{ row.steps }} / {{ row.compatible_steps || 0 }}</dd></div><div><dt>含拦截/确认会话</dt><dd>{{ row.flagged }}</dd></div></dl>
                  <div class="baseline-device-foot"><span class="baseline-note">{{ fmtTs(row.first) }} 至 {{ fmtTs(row.last) }}</span><el-popconfirm :title="'清空 ' + row.device + ' 的记录？'" confirm-button-text="清空" cancel-button-text="取消" @confirm="clearDevice(row.device)"><template #reference><el-button link type="danger" size="small" :disabled="busy">清空记录</el-button></template></el-popconfirm></div>
                </article>
              </div>
            </section>
            <section class="baseline-card baseline-training" aria-labelledby="baseline-training-title">
              <div class="baseline-card-head"><h3 id="baseline-training-title"><span class="baseline-step" aria-hidden="true">2</span>训练候选模型</h3><el-button link size="small" :disabled="busy" @click="resetForm">恢复默认</el-button></div>
              <el-form class="baseline-train-form compact-controls" label-position="top" size="small" :disabled="training || !!mutation" @submit.prevent="train">
                <el-form-item label="外部数据集">
                  <el-select v-model="form.dataset_id" aria-label="外部数据集">
                    <el-option label="不使用" value="" />
                    <el-option v-for="dataset in datasets" :key="dataset.id" :label="dataset.name" :value="dataset.id" :disabled="!dataset.available" />
                  </el-select>
                </el-form-item>
                <template v-if="form.dataset_id">
                  <el-form-item label="外部训练会话数">
                    <el-select v-model="form.dataset_limit" aria-label="外部训练会话数">
                      <el-option :label="`全部（${externalDataset?.train?.sessions || 0} 个）`" :value="0" />
                      <el-option v-for="size in datasetSizes" :key="size" :label="`${size} 个`" :value="size" />
                    </el-select>
                  </el-form-item>
                  <el-form-item label="计数方式">
                    <template #label><span>计数方式</span><el-tooltip content="来源平衡按内置 25%、SWE-chat 75% 分配计数，每个来源内会话等权，仅训练共享模型。混合真实会话或使用设备个性化时请选择原始计数。外部验证分区固定，保留测试不进入页面训练或评估。" :show-after="200"><button type="button" class="baseline-help" aria-label="计数方式说明">?</button></el-tooltip></template>
                    <el-select v-model="form.dataset_balance" aria-label="计数方式">
                      <el-option :label="form.use_corpus ? '来源平衡（内置 25% / SWE-chat 75%）' : '会话等权（SWE-chat）'" value="balanced" />
                      <el-option label="原始计数（可混合真实会话）" value="raw" />
                    </el-select>
                  </el-form-item>
                </template>
                <el-form-item label="评分机制">
                  <template #label><span>评分机制</span><el-tooltip content="递归插值默认使用最近三个行为符号，证据不足时逐级回退；默认按训练分组折外分数的 99 分位标定，约对应 1% 训练触发预算。旧的一阶模型可继续加载和回滚，独立性能验收状态保留在模型报告中。" :show-after="200"><button type="button" class="baseline-help" aria-label="评分机制说明">?</button></el-tooltip></template>
                  <el-select v-model="form.scoring_mode" aria-label="评分机制">
                    <el-option label="递归插值马尔可夫（默认三阶）" value="interpolated" />
                    <el-option label="原有计数" value="legacy" />
                    <el-option label="证据计数与回退（实验）" value="evidence" />
                    <el-option label="仅证据回退（消融）" value="backoff" />
                  </el-select>
                </el-form-item>
                <div class="baseline-source"><div><label for="baseline-corpus">内置模拟语料</label></div><el-switch id="baseline-corpus" v-model="form.use_corpus" aria-label="使用内置语料" /></div>
                <div class="baseline-source"><div class="baseline-source-label"><label for="baseline-recorded">真实会话</label><p class="baseline-note">{{ selected.length ? '已选 ' + selected.length + ' 台设备' : '全部设备' }} · 当前版本已执行 {{ selectedSessions }} 个会话</p></div><el-switch id="baseline-recorded" v-model="form.use_recorded" :disabled="balancedDataset" aria-label="使用真实会话" /></div>
                <el-form-item label="含拦截 / 确认记录的处理" class="baseline-train-wide">
                  <el-select v-model="form.exclude_flagged" :disabled="!form.use_recorded" aria-label="拦截记录排除方式"><el-option label="排除整个会话（默认）" value="session" /><el-option label="仅剔除拦截 / 确认步骤" value="step" /><el-option label="不排除（实验用途）" value="none" /></el-select>
                </el-form-item>
                <div class="baseline-source"><div><label for="baseline-personalize">按设备个性化</label></div><el-switch id="baseline-personalize" v-model="form.personalize" :disabled="balancedDataset || evidenceMode || !form.use_recorded" aria-label="按设备个性化" /></div>
                <details class="baseline-advanced">
                  <summary>高级训练参数</summary>
                  <div class="baseline-advanced-body">
                    <template v-if="evidenceMode">
                      <el-form-item v-if="form.scoring_mode === 'interpolated'" label="最大历史阶数"><el-input-number v-model="form.markov_order" :min="1" :max="8" :precision="0" controls-position="right" aria-label="最大历史阶数" /></el-form-item>
                      <el-form-item label="证据粒度"><el-select v-model="form.evidence_granularity" aria-label="证据粒度"><el-option label="仓库 / 来源组" value="group" /><el-option label="会话" value="session" /><el-option label="事件（消融）" value="event" /></el-select></el-form-item>
                      <el-form-item label="证据回退强度 K"><el-input-number v-model="form.evidence_k" :min="0.001" :max="100000" :step="0.001" controls-position="right" aria-label="证据回退强度 K" /></el-form-item>
                      <el-form-item v-if="form.scoring_mode === 'evidence' || form.scoring_mode === 'interpolated'" label="先验证据强度"><el-input-number v-model="form.evidence_prior" :min="0.001" :max="100000" :step="0.001" controls-position="right" aria-label="先验证据强度" /></el-form-item>
                    </template>
                    <el-form-item v-if="form.personalize && form.use_recorded" label="个性化所需最少会话"><el-input-number v-model="form.min_device_sessions" :min="1" :max="1000" :precision="0" controls-position="right" aria-label="个性化所需最少会话数" /></el-form-item>
                    <el-form-item v-if="form.use_recorded" label="接入会话最近天数"><el-input-number v-model="form.since_days" :min="0" :max="3650" :precision="0" controls-position="right" aria-label="最近天数" /></el-form-item>
                    <el-form-item v-if="form.use_recorded" label="时间衰减半衰期（天）"><el-input-number v-model="form.half_life_days" :min="0" :max="3650" controls-position="right" aria-label="半衰期天数" /></el-form-item>
                    <el-form-item label="固定阈值" class="baseline-threshold">
                      <template #label><span>固定阈值</span><el-button link type="primary" size="small" :disabled="!active?.threshold || busy" @click="form.threshold = active.threshold">沿用当前 {{ active?.threshold }}</el-button></template>
                      <el-input-number v-model="form.threshold" :min="0" :max="30" :step="0.1" :precision="2" controls-position="right" aria-label="固定阈值" />
                    </el-form-item>
                    <el-form-item label="自动标定分位数"><el-input-number v-model="form.quantile" :disabled="form.threshold > 0" :min="50" :max="99.9" :step="0.5" controls-position="right" aria-label="阈值分位" /></el-form-item>
                    <el-form-item v-if="form.use_recorded" label="接入会话留出比例"><el-input-number v-model="form.holdout" :min="0" :max="0.5" :step="0.05" :precision="2" controls-position="right" aria-label="留出比例" /></el-form-item>
                  </div>
                </details>
                <p v-if="!hasSource" class="baseline-note c-med" role="status">请至少选择一种数据来源。</p>
                <p v-if="form.dataset_id && !externalDataset?.available" class="baseline-note c-med" role="status">所选外部数据集不可用，请刷新或重新选择。</p>
                <el-alert v-if="trainError" :title="trainError" class="baseline-operation-error" type="error" :closable="false" show-icon />
                <div class="baseline-train-actions"><el-button type="primary" native-type="submit" :loading="training" :disabled="busy || !hasSource || !!form.dataset_id && !externalDataset?.available">{{ training ? '正在训练…' : '开始训练' }}</el-button></div>
              </el-form>
            </section>
          </div>
          <!-- 候选评估区 -->
          <section v-if="lastTrained" ref="resultEl" tabindex="-1" class="bl-result baseline-result" aria-labelledby="baseline-result-title">
            <div class="bl-result-head">
              <h3 id="baseline-result-title"><span class="baseline-step" aria-hidden="true">3</span>评估候选模型 <span class="mono">{{ lastTrained.version }}</span></h3>
              <span class="grow"></span>
              <el-button size="small" :type="verdict.type === 'error' ? 'default' : 'primary'"
                         :loading="mutation === 'activate:' + lastTrained.version" :disabled="busy || lastTrained.compatible === false || lastTrained.version === baselineData.active" @click="activate(lastTrained.version)">
                {{ lastTrained.version === baselineData.active ? '已启用' : '启用此模型' }}</el-button>
            </div>
            <p class="baseline-note">{{ dataText(lastTrained) }} · {{ lastTrained.meta.train_steps }} 个训练步骤。
              {{ skippedText(lastTrained.meta.skipped) }}</p>
            <p v-if="lastTrained.meta.external_source" class="baseline-note">外部训练 {{ lastTrained.meta.external_sessions }} 个会话 · 验证共 {{ lastTrained.meta.holdout_sessions }} 个会话 · 保留测试 {{ lastTrained.meta.external_source.reserved_test?.sessions || lastTrained.meta.external_source.test_sessions || 0 }} 个会话</p>
            <dl v-if="lastTrained.meta.scoring" class="baseline-stats">
              <div><dt>符号出现次数</dt><dd>{{ lastTrained.meta.scoring.global.raw_count }}</dd></div>
              <div><dt>分组支持数</dt><dd>{{ lastTrained.meta.scoring.global.group_support }}</dd></div>
              <div><dt>证据折算值</dt><dd class="mono">{{ Number(lastTrained.meta.scoring.effective_n).toFixed(2) }}</dd></div>
            </dl>
            <el-alert v-if="activationError" :title="activationError" type="error" :closable="false" show-icon class="my-12" />

            <el-alert :type="verdict.type" :title="verdict.title" :closable="false" show-icon class="my-12">
              <ul class="bl-checks">
                <li v-for="c in checkRows" :key="c.id" :class="'bl-check-' + c.level">
                  <el-tag size="small" effect="plain" :type="LEVEL_TAG[c.level]">{{ LEVEL_TEXT[c.level] }}</el-tag>
                  <b>{{ c.label }}</b><span class="mono" v-if="c.value">{{ c.value }}</span><span>{{ c.text }}</span>
                </li>
              </ul>
            </el-alert>

            <details class="baseline-result-details"><summary>真实会话去向</summary>
            <el-table :data="lastTrained.meta.device_report || []" size="small" class="bl-compare"
                      empty-text="本次未使用真实会话（未开启「真实会话」或还没有记录）">
              <el-table-column label="设备" min-width="140"><template #default="{row}"><span class="mono">{{ row.device }}</span></template></el-table-column>
              <el-table-column label="会话" width="60" align="right" prop="sessions"></el-table-column>
              <el-table-column label="排除" min-width="200">
                <template #default="{row}"><span class="fs-11">{{ excludedText(row) }}</span></template>
              </el-table-column>
              <el-table-column label="参与训练" width="80" align="right"><template #default="{row}"><b>{{ row.train }}</b></template></el-table-column>
              <el-table-column label="留出评估" width="80" align="right" prop="holdout"></el-table-column>
              <el-table-column label="个性化" min-width="150">
                <template #default="{row}">
                  <el-tag v-if="row.personalized" size="small" type="success" effect="plain">已个性化</el-tag>
                  <span v-else class="fs-11 muted">{{ personalizeText(row) }}</span>
                </template>
              </el-table-column>
            </el-table>
            </details><details class="baseline-result-details"><summary>详细指标对比<span>{{ lastTrained.meta.compare ? '当前模型在同一份留出数据与夹具上重新评估' : '旧版报告：当前模型指标来自历史元数据' }}</span></summary>
            <el-table :data="compareRows" size="small" class="bl-compare">
              <el-table-column label="指标" min-width="210">
                <template #default="{row}"><span>{{ row.label }}</span></template>
              </el-table-column>
              <el-table-column :label="'当前 · ' + (cmp.version || active?.version || '')" min-width="150">
                <template #default="{row}"><span class="mono">{{ row.current }}</span></template>
              </el-table-column>
              <el-table-column label="本次训练" min-width="150">
                <template #default="{row}"><span class="mono" :class="row.tone">{{ row.next }}</span></template>
              </el-table-column>
            </el-table>
            </details>
          </section>
        </el-tab-pane>
        <el-tab-pane label="性能比较" name="comparison">
          <BaselineComparison v-if="panel === 'comparison' && tab === 'baseline'" :models="baselineData.models" :active="baselineData.active" />
        </el-tab-pane>
        <el-tab-pane :label="'模型版本 · ' + (baselineData.models?.length || 0)" name="models">
          <section class="baseline-card baseline-models" aria-labelledby="baseline-models-title">
            <div class="baseline-card-head"><h3 id="baseline-models-title">模型版本</h3><el-button size="small" @click="panel = 'training'">训练新模型</el-button></div>

            <el-table :data="baselineData.models" size="small" row-key="version">
              <el-table-column label="版本" min-width="190">
                <template #default="{row}"><span class="mono">{{ row.version }}</span>
                  <el-tag v-if="row.active" size="small" type="success" effect="dark">使用中</el-tag>
                  <el-tag v-if="row.score_semantics_version === 3" size="small" type="info" effect="plain">{{ row.order }} 阶插值</el-tag>
                  <el-tag v-if="row.version === 'builtin-legacy'" size="small" effect="plain">原始一阶回滚</el-tag>
                  <el-tag v-if="row.score_semantics_version === 2" size="small" type="info" effect="plain">{{ row.params?.scoring_mode === 'backoff' ? '证据回退' : '证据计数' }} · 实验</el-tag>
                  <el-tag v-if="row.compatible === false" size="small" type="warning" effect="plain"
                          :title="row.incompatibility_reason">版本不兼容，需重训</el-tag></template>
              </el-table-column>
              <el-table-column label="训练时间" width="160"><template #default="{row}">{{ row.builtin ? '随规则发布' : fmtTs(row.created_at) }}</template></el-table-column>
              <el-table-column label="训练数据" min-width="170"><template #default="{row}">{{ dataText(row) }}</template></el-table-column>
              <el-table-column label="阈值" width="70" align="right"><template #default="{row}"><span class="mono">{{ row.threshold }}</span></template></el-table-column>
              <el-table-column label="夹具 AUC" width="70" align="right"><template #default="{row}"><span class="mono">{{ fmtNum(row.meta?.auc) }}</span></template></el-table-column>
              <el-table-column label="留出真实步骤超阈值" width="140" align="right">
                <template #default="{row}"><span class="mono">{{ ratio(row.meta?.holdout_over_threshold, row.meta?.holdout_steps) }}</span></template>
              </el-table-column>
              <el-table-column label="正常夹具超阈值" width="120" align="right">
                <template #default="{row}"><span class="mono">{{ ratio(row.meta?.fixture_benign_over_threshold, row.meta?.fixture_benign_steps) }}</span></template>
              </el-table-column>
              <el-table-column label="攻击夹具风险点" width="110" align="right">
                <template #default="{row}"><span class="mono">{{ ratio(row.meta?.fixture_risk_over_threshold, row.meta?.fixture_risk_steps) }}</span></template>
              </el-table-column>
              <el-table-column label="操作" width="120" fixed="right">
                <template #default="{row}">
                  <el-button v-if="!row.active" link type="primary" size="small" :disabled="busy || row.compatible === false"
                             :title="row.incompatibility_reason || ''" @click="activate(row.version)">{{ row.version === 'builtin-legacy' ? '回滚到一阶' : '启用' }}</el-button>
                  <el-popconfirm v-if="!row.active && !row.builtin" :title="'删除模型 ' + row.version + '？'" confirm-button-text="删除"
                                 cancel-button-text="取消" @confirm="removeModel(row.version)">
                    <template #reference><el-button link type="danger" size="small" :disabled="busy">删除</el-button></template>
                  </el-popconfirm>
                </template>
              </el-table-column>
            </el-table>
          </section>
        </el-tab-pane>
      </el-tabs>
    </template>
    <el-skeleton v-else-if="!adminNeedsToken" :rows="5" animated />
  </section>
</template>

<script setup>
import { computed, nextTick, reactive, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { Refresh } from "../icons";
import AgentIcon from "../components/AgentIcon.vue";
import BaselineComparison from "../components/BaselineComparison.vue";
import { tab, AGENT_NAMES } from "../store/runtime";
import { adminToken, adminNeedsToken } from "../store/devices";
import {
  baselineData, baselineLoaded, baselineError, lastTrained,
  refreshBaseline, trainBaseline, activateBaseline, deleteBaseline, clearRecords,
} from "../store/baseline";

const selected = ref([]);
const panel = ref("training");
const training = ref(false);
const trainError = ref("");
const activationError = ref("");
const refreshing = ref(false);
const mutation = ref("");
const resultEl = ref(null);
const form = reactive({});
const resetForm = () => { if (!busy.value) Object.assign(form, baselineData.value.defaults || {}); };
const records = computed(() => baselineData.value.data || {});
const datasets = computed(() => baselineData.value.datasets || []);
const externalDataset = computed(() => datasets.value.find(dataset => dataset.id === form.dataset_id));
const datasetSizes = computed(() => [263, 1000].filter(size => size < (externalDataset.value?.train?.sessions || 0)));
const balancedDataset = computed(() => !!form.dataset_id && form.dataset_balance === 'balanced');
const evidenceMode = computed(() => !!form.scoring_mode && form.scoring_mode !== 'legacy');
const hasSource = computed(() => form.use_corpus || form.use_recorded || !!form.dataset_id);
watch(balancedDataset, (balanced) => {
  if (balanced) { form.use_recorded = false; form.personalize = false; }
});
watch(evidenceMode, (enabled) => { if (enabled) form.personalize = false; });
watch(() => form.dataset_id, () => { form.dataset_limit = 0; });
const devices = computed(() => records.value.devices || []);
const allSelected = computed(() => !!devices.value.length && selected.value.length === devices.value.length);
const selectedSessions = computed(() => devices.value.filter(row => !selected.value.length || selected.value.includes(row.device))
  .reduce((sum, row) => sum + (row.compatible_sessions || 0), 0));
const selectAll = (checked) => { selected.value = checked ? devices.value.map(row => row.device) : []; };
const selectDevice = (device, checked) => {
  selected.value = checked ? [...new Set([...selected.value, device])] : selected.value.filter(id => id !== device);
};

const scoring = computed(() => baselineData.value.enabled && baselineData.value.model_compatible !== false);

const active = computed(() => baselineData.value.models.find((m) => m.active));
const busy = computed(() => training.value || refreshing.value || !!mutation.value);

const fmtNum = (v) => (v === null || v === undefined ? "—" : Number(v).toFixed(3));
const ratio = (part, whole) => (whole ? `${part}/${whole}（${((part / whole) * 100).toFixed(1)}%）` : "—");
const kb = (bytes) => (bytes > 1048576 ? (bytes / 1048576).toFixed(1) + " MB" : Math.ceil(bytes / 1024) + " KB");
const fmtTs = (t) => (t ? new Date(t * 1000).toLocaleString("zh-CN", { hour12: false }) : "—");
const dataText = (m) => {
  const meta = m?.meta || {};
  if (!meta.train_sessions) return "—";
  const parts = [`内置 ${meta.corpus_sessions || 0}`];
  if (meta.external_sessions) parts.push(`SWE-chat ${meta.external_sessions}`);
  parts.push(`接入 ${meta.recorded_sessions || 0}`);
  return `${parts.join(" + ")} 个会话`;
};

// 当前模型的对照指标：训练时在同一份留出数据上重新评估（旧版训练结果没有 compare 时退回模型自身的 meta）。
const cmp = computed(() => lastTrained.value?.meta?.compare || active.value?.meta || {});
const comparisonModel = computed(() => baselineData.value.models.find(model => model.version === cmp.value.version) || active.value);

const pct = (v) => (v === null || v === undefined ? "—" : (v * 100).toFixed(1) + "%");
const LEVEL_TAG = { ok: "success", warn: "warning", fail: "danger" };
const LEVEL_TEXT = { ok: "通过", warn: "注意", fail: "不通过" };
const VERDICTS = {
  recommend: { type: "success", title: "建议启用：本次留出数据与固定夹具的检查通过" },
  review: { type: "warning", title: "需要人工判断：本次评估证据不足以确认改善" },
  reject: { type: "error", title: "不建议启用：本次评估存在未通过项，请检查训练数据与参数" },
};
const verdict = computed(() => VERDICTS[lastTrained.value?.meta?.assessment?.verdict] || VERDICTS.review);

const CHECKS = {
  evidence_validation: { label: "新评分机制验收", text: () => "当前为实验候选，尚缺独立测试验收", value: () => "待验收" },
  external_review: { label: "外部数据复核", text: () => "规则标记尚未经人工核验，需结合会话上下文判断",
    value: (c) => `${c.candidate || 0} 个标记步骤` },
  data: { label: "筛选后真实会话（含留出）", text: (c) => (c.level === "ok" ? "达到本次评估的样本量检查要求"
    : c.candidate ? "少于 20 个会话，模型主要仍由内置语料决定，效果差异有限" : "没有使用真实会话，等同于重新训练内置语料"),
    value: (c) => c.candidate + " 个会话" },
  holdout: { label: "留出真实步骤超阈值", text: (c) => (c.candidate == null
    ? `本次没有可用的留出步骤；需开启留出评估，且筛选后真实会话不少于 ${lastTrained.value?.meta?.holdout_min || 10} 个`
    : c.level === "ok" ? "在本次留出数据上不高于当前模型" : "在本次留出数据上高于当前模型"),
    value: (c) => (c.candidate == null ? "" : `${pct(c.candidate)}（当前 ${pct(c.active)}）`) },
  benign: { label: "正常夹具超阈值", text: (c) => ({ ok: "未超过本次正常夹具的检查阈值",
    warn: "比当前模型上升超过 1 个百分点", fail: "固定正常夹具超阈值比例超过 3%，请检查训练数据是否过于单一" })[c.level],
    value: (c) => `${pct(c.candidate)}（当前 ${pct(c.active)}）` },
  risk: { label: "攻击夹具风险点超阈值", text: (c) => (c.level === "ok" ? "未超过本次夹具评估的退化阈值" : thresholdShift.value
    ? `阈值从 ${cmp.value.threshold} 升到 ${lastTrained.value.threshold}，AUC 未超过退化阈值；可沿用阈值 ${cmp.value.threshold} 对照训练`
    : c.level === "warn" ? "比当前模型下降超过 3 个百分点"
      : "固定攻击夹具下降超过 10 个百分点，请检查是否混入攻击会话"),
    value: (c) => `${pct(c.candidate)}（当前 ${pct(c.active)}）` },
  auc: { label: "夹具 AUC", text: (c) => ({ ok: "未超过本次夹具 AUC 的退化阈值",
    warn: "比当前模型低 0.02 以上", fail: "低于本页 0.80 的检查阈值" })[c.level],
    value: (c) => `${fmtNum(c.candidate)}（当前 ${fmtNum(c.active)}）` },
};
// 风险点下降但 AUC 没变差、阈值升高：是阈值标定的抽样波动，不是模型学坏了。
const thresholdShift = computed(() => {
  const next = lastTrained.value?.meta || {};
  const auc = next.assessment?.checks?.find((c) => c.id === "auc");
  return auc?.level === "ok" && cmp.value.threshold !== undefined && lastTrained.value.threshold > cmp.value.threshold;
});
const checkRows = computed(() => (lastTrained.value?.meta?.assessment?.checks || []).map((c) => ({
  id: c.id, level: c.level, label: CHECKS[c.id]?.label || c.id, text: CHECKS[c.id]?.text(c) || "", value: CHECKS[c.id]?.value(c) || "",
})));

const excludedText = (row) => {
  if (!row.selected) return "未勾选该设备";
  const parts = [];
  if (row.incompatible_records) parts.push(`${row.incompatible_records} 条版本不兼容记录`);
  if (row.old) parts.push(`${row.old} 个超出最近天数`);
  if (row.flagged) parts.push(`${row.flagged} 个含拦截/确认`);
  if (row.flagged_steps) parts.push(`剔除 ${row.flagged_steps} 个拦截/确认步骤`);
  return parts.join(" · ") || "无";
};
const personalizeText = (row) => {
  const params = lastTrained.value?.params || {};
  if (!params.personalize) return "未开启";
  if (!row.selected || !row.train) return "—";
  return `参与训练的会话 ${row.train} < ${params.min_device_sessions}`;
};

const compareRows = computed(() => {
  const cur = cmp.value;
  const next = lastTrained.value?.meta || {};
  const better = (a, b, higher) => (a === undefined || b === undefined || a === b ? "" : (higher ? b > a : b < a) ? "c-ok" : "c-crit");
  const rate = (m, part, whole) => (m[whole] ? m[part] / m[whole] : undefined);
  return [
    { label: "训练数据", current: dataText(comparisonModel.value), next: dataText(lastTrained.value), },
    { label: "阈值", current: cur.threshold ?? active.value?.threshold, next: lastTrained.value?.threshold, },
    { label: "留出真实步骤超阈值", current: ratio(cur.holdout_over_threshold, cur.holdout_steps),
      next: ratio(next.holdout_over_threshold, next.holdout_steps),
      tone: better(rate(cur, "holdout_over_threshold", "holdout_steps"), rate(next, "holdout_over_threshold", "holdout_steps"), false),
      },
    { label: "正常夹具超阈值", current: ratio(cur.fixture_benign_over_threshold, cur.fixture_benign_steps),
      next: ratio(next.fixture_benign_over_threshold, next.fixture_benign_steps),
      tone: better(cur.fixture_benign_over_threshold, next.fixture_benign_over_threshold, false), },
    { label: "攻击夹具风险点超阈值", current: ratio(cur.fixture_risk_over_threshold, cur.fixture_risk_steps),
      next: ratio(next.fixture_risk_over_threshold, next.fixture_risk_steps),
      tone: better(cur.fixture_risk_over_threshold, next.fixture_risk_over_threshold, true),
      },
    { label: "AUC（风险点 vs 正常步骤）", current: fmtNum(cur.auc), next: fmtNum(next.auc), tone: better(cur.auc, next.auc, true),
      },
    { label: "个性化设备", current: (comparisonModel.value?.meta?.personalized_devices || []).join("、") || "无",
      next: (next.personalized_devices || []).join("、") || "无", },
  ];
});
const skippedText = (s) => (s ? `排除：版本不兼容记录 ${s.incompatible_records || 0} 条 · 过旧会话 ${s.old} 个 · 含拦截/确认会话 ${s.flagged} 个 · 拦截/确认步骤 ${s.flagged_steps || 0} 步 · 未选设备会话 ${s.device} 个` : "—");

async function train() {
  if (busy.value || refreshing.value || !hasSource.value || form.dataset_id && !externalDataset.value?.available) return;
  trainError.value = "";
  activationError.value = "";
  training.value = true;
  try {
    const params = { ...form, devices: [...selected.value] };
    const result = await trainBaseline(params);
    if (result) {
      panel.value = "training";
      ElMessage.success("训练完成，确认评估结果后再启用");
      await nextTick();
      resultEl.value?.scrollIntoView({ block: "start", behavior: "instant" });
      resultEl.value?.focus({ preventScroll: true });
    } else trainError.value = baselineError.value;
  } finally {
    training.value = false;
  }
}

async function activate(version) {
  const model = baselineData.value.models.find(row => row.version === version) || lastTrained.value;
  if (busy.value || model?.compatible === false || version === baselineData.value.active) return;
  activationError.value = "";
  mutation.value = "activate:" + version;
  try {
    if (await activateBaseline(version)) ElMessage.success("已启用 " + version + "，新的行为打分使用该模型");
    else activationError.value = baselineError.value;
  } finally { mutation.value = ""; }
}

async function clearAll() {
  await clearDevice();
}

async function clearDevice(device = "") {
  if (busy.value) return;
  mutation.value = "clear";
  try {
    const removed = await clearRecords(device);
    if (removed !== null) ElMessage.success(`已清空 ${removed} 条记录，已训练模型保留`);
  } finally { mutation.value = ""; }
}

async function removeModel(version) {
  if (busy.value) return;
  mutation.value = "delete:" + version;
  try { await deleteBaseline(version); } finally { mutation.value = ""; }
}

async function reload() {
  if (refreshing.value || busy.value) return;
  refreshing.value = true;
  try { await refreshBaseline(); } finally { refreshing.value = false; }
}

watch(tab, (t) => { if (t === "baseline") reload(); }, { immediate: true });
watch(devices, (rows) => { selected.value = selected.value.filter(id => rows.some(row => row.device === id)); });
// 默认参数来自服务端；需要先输入令牌时，加载成功后再填充表单。
watch(() => baselineData.value.defaults, (defaults) => {
  if (defaults && Object.keys(defaults).length && !Object.keys(form).length) Object.assign(form, defaults);
}, { immediate: true });
</script>

<style scoped>
.baseline-page-head, .baseline-card-head, .baseline-source, .baseline-selection { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.baseline-page-head { margin-bottom:16px; }
.baseline-overview { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.baseline-card { min-width: 0; padding:var(--space-4); border: 1px solid var(--line); border-radius:var(--radius-panel); background: var(--panel); }
.baseline-card h3, .baseline-result h3 { margin: 0; color: var(--title); font-size: 14px; font-weight: 500; }
.baseline-card-head { margin-bottom: 12px; }
.baseline-card-head h3, .baseline-result h3 { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.baseline-version { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; min-height: 28px; }
.baseline-version strong { overflow-wrap: anywhere; font-size: 15px; color: var(--title); }
.baseline-note { margin: 4px 0 0; color: var(--muted); font-size: 12px; line-height: 1.7; }
.baseline-wrap { overflow-wrap: anywhere; }
.baseline-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 12px 0 8px; }
.baseline-stats dt, .baseline-device-counts dt { color: var(--muted); font-size: 12px; }
.baseline-stats dd { margin: 2px 0 0; font-size: 24px; font-weight: 600; color: var(--title); line-height: 1.5; }
.baseline-stats small { font-size: 12px; font-weight: 400; color: var(--muted); }
.baseline-data-stats { grid-template-columns: 1fr 1fr; margin-top: 12px; }
.baseline-data-stats > div + div { border-left: 1px solid var(--line); padding-left: 20px; }
.baseline-data-stats > div > span { color: var(--muted); font-size: 12px; }
.baseline-tabs { margin-top: 16px; }
.baseline-tabs :deep(.el-tabs__header) { margin-bottom: 16px; }
.baseline-tabs :deep(.el-tabs__item) { font-size: 13px; height: var(--control-tab-height); }
.baseline-workspace { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(400px, 1fr); gap: 16px; align-items: start; }
.baseline-step { display: inline-flex; flex: none; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 7px; background: var(--brand-bg); color: var(--brand); font: 600 12px var(--mono); }
.baseline-record-warning { margin-top: 12px; }
.baseline-selection { min-height: 42px; flex-wrap: wrap; gap: 4px 12px; margin: 10px 0; border-top: 1px solid var(--line-2); }
.baseline-selection > span { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; }
.baseline-device-name { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; overflow-wrap: anywhere; }
.baseline-device-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; margin-top: 4px; color: var(--muted); font-size: 12px; }
.baseline-agent { display: inline-flex; align-items: center; gap: 4px; }
.baseline-agent :deep(.agent-icon) { padding: 2px; border-radius: 5px; }
.baseline-device-cards { display: none; }
.baseline-source { min-width: 0; padding: 6px 0; border-bottom: 1px solid var(--line-2); }
.baseline-source label { color: var(--title); font-size: 13px; cursor: pointer; }
.baseline-source .el-switch { flex: none; }
.baseline-source-label { display: flex; align-items: baseline; flex-wrap: wrap; gap: 2px 8px; min-width: 0; }
.baseline-datasets { margin: 14px 0; }
.baseline-datasets h4 { margin: 0 0 10px; color: var(--text); font-size: 13px; font-weight: 500; }
.baseline-dataset { padding: 12px; border: 1px solid var(--line-2); border-radius: 8px; margin-top: 8px; }
.baseline-dataset-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 13px; }
.baseline-dataset-counts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 10px 0 0; font-size: 12px; }
.baseline-dataset-counts dt { color: var(--muted); }
.baseline-dataset-counts dd { margin: 4px 0 0; color: var(--text); }
.baseline-help { width: 16px; height: 16px; padding: 0; margin-left: 6px; border: 1px solid var(--muted); border-radius: 50%; background: transparent; color: var(--muted); font-size: 11px; cursor: help; }
.baseline-train-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; align-items: start; }
.baseline-train-form > :is(.baseline-source, .baseline-train-wide, .baseline-advanced, .baseline-train-actions, .baseline-operation-error, p) { grid-column: 1 / -1; }
.baseline-train-form :deep(.el-form-item) { min-width: 0; margin: 0; }
.baseline-train-form :deep(.el-form-item__label) { margin-bottom: 4px; font-size: 13px; }
.baseline-train-form :deep(.el-form-item__content) { display: block; }
.baseline-train-form .baseline-note { margin-top: 4px; }
.baseline-train-form .baseline-source-label .baseline-note { margin: 0; }
.baseline-advanced { min-width: 0; border: 1px solid var(--line); border-radius: 8px; }
.baseline-advanced summary, .baseline-result-details summary { padding: 10px 12px; color: var(--text); font-size: 13px; cursor: pointer; }
.baseline-advanced summary { padding: 8px 12px; }
.baseline-advanced summary:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; border-radius: 8px; }
.baseline-advanced summary > span, .baseline-result-details summary > span { display: block; margin: 2px 0 0 14px; color: var(--muted); font-size: 12px; }
.baseline-advanced-body { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; border-top: 1px solid var(--line); padding: 12px; }
.baseline-advanced :deep(.el-input-number) { width: 100%; }
.baseline-threshold :deep(.el-form-item__label) { display: flex; align-items: center; justify-content: space-between; gap: 4px; }
.baseline-threshold :deep(.el-form-item__label .el-button) { min-height: 20px; font-size: 12px; }
.baseline-advanced .baseline-note .el-button { margin-left: 8px; }
.baseline-train-actions { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 8px 12px; }
.baseline-result { margin-top: 16px; padding: 18px; scroll-margin-top: 16px; }
.baseline-result:focus-visible { outline: 2px solid var(--brand); outline-offset: 3px; }
.baseline-result h3 .mono { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
.baseline-result :deep(.el-alert__content) { min-width: 0; }
.baseline-result .bl-result-head { flex-wrap: wrap; }
.baseline-result .bl-checks { gap: 8px; margin: 12px 0 0; }
.baseline-result-details { border-top: 1px solid var(--line); margin-top: 12px; }
.baseline-result-details summary { padding-left: 0; }
.baseline-models > .el-table { margin-top: 16px; }
.baseline-empty { text-align: center; padding: 24px 8px; font-size: 12px; color: var(--muted); }
@media (max-width: 1200px) {
  .baseline-workspace { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 760px) {
  .baseline-overview { grid-template-columns: minmax(0, 1fr); gap: 12px; }
  .baseline-card { padding: 16px; }
  .baseline-workspace { gap: 12px; }
}
@media (max-width: 600px) {
  .baseline-page-head { align-items: flex-start; }
  .baseline-card-head { gap: 8px; }
  .baseline-card-head h3 { font-size: 13px; }
  .baseline-card { padding: 14px; }
  .baseline-stats { gap: 12px; }
  .baseline-stats dd { font-size: 20px; }
  .baseline-data-stats > div + div { padding-left: 12px; }
  .baseline-device-table { display: none; }
  .baseline-device-cards { display: grid; gap: 10px; max-height: 390px; overflow-y: auto; }
  .baseline-device-card { min-width: 0; padding: 10px; border: 1px solid var(--line); border-radius: 8px; }
  .baseline-device-card > .el-checkbox { display: flex; height: auto; min-height: 32px; white-space: normal; }
  .baseline-device-card :deep(.el-checkbox__label) { min-width: 0; overflow-wrap: anywhere; }
  .baseline-device-card :deep(.el-checkbox__input) { flex: none; }
  .baseline-device-counts { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 12px 0; }
  .baseline-device-counts dd { margin: 2px 0 0; color: var(--title); font-size: 14px; }
  .baseline-device-foot { display: flex; align-items: center; gap: 8px; }
  .baseline-device-foot > span { min-width: 0; flex: 1; }
  .baseline-training .baseline-train-form, .baseline-advanced-body { grid-template-columns: minmax(0, 1fr); }
  .baseline-result { padding: 14px; }
  .baseline-page :deep(.el-button--small), .baseline-page :deep(.el-checkbox), .baseline-page :deep(.el-switch) { min-height: var(--control-height); }
  .baseline-train-actions .el-button { min-height: var(--control-height); }
  .baseline-tabs :deep(.el-tabs__item) { padding: 0 12px; }
}
</style>
