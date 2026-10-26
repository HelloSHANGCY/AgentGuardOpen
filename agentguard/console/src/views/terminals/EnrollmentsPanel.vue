<template>
  <div>
    <h3 class="sub-title enrollment-heading">待认证设备 <el-tag size="small" type="warning" effect="light">{{ deviceData.enrollments.length }}</el-tag></h3>

    <el-table :data="deviceData.enrollments" empty-text="暂无待认证的接入申请" size="small" class="enroll-table">
      <el-table-column label="主机" min-width="170">
        <template #default="{row}">
          <div>{{ row.host?.hostname || '—' }}</div>
          <div class="muted fs-11">{{ row.host?.os || '' }}{{ row.host?.user ? ' · ' + row.host.user : '' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="网络" min-width="160">
        <template #default="{row}">
          <DeviceNetwork :host="row.host" :remote-ip="row.remote_ip" :name="row.host?.hostname || row.enrollment_id" />
        </template>
      </el-table-column>
      <el-table-column label="申请的 Agent" min-width="150">
        <template #default="{row}">
          <el-tag v-for="a in row.agents" :key="a" size="small" effect="plain" class="mr-4">{{ AGENT_NAMES[a] || a }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="核对码" width="110">
        <template #default="{row}"><span class="mono enroll-code">{{ row.code }}</span></template>
      </el-table-column>
      <el-table-column label="申请时间" width="150">
        <template #default="{row}">
          <span :title="row.created_at">{{ short(row.created_at) }}</span>
          <div class="muted fs-11 mono">{{ row.client || '' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="110" fixed="right">
        <template #default="{row}">
          <el-button link type="primary" size="small" @click="openApprove(row)">认证</el-button>
          <el-popconfirm :title="'拒绝 ' + (row.host?.hostname || row.enrollment_id) + ' 的接入申请？'" confirm-button-text="拒绝"
                         cancel-button-text="取消" @confirm="rejectEnrollment(row.enrollment_id)">
            <template #reference><el-button link type="danger" size="small">拒绝</el-button></template>
          </el-popconfirm>
        </template>
      </el-table-column>
    </el-table>

    <!-- 认证待接入设备：核对核对码，确定设备 ID、使用人、策略档案与允许的 Agent -->
    <el-dialog v-model="approveOpen" title="认证设备" width="600px" class="detail-dialog">
      <template v-if="approving">
        <div class="enroll-verify">
          <div class="muted fs-11">核对码</div>
          <div class="mono enroll-code big">{{ approving.code }}</div>
          <div class="muted fs-11">{{ approving.host?.hostname || '—' }} · {{ approving.host?.os || '—' }} · {{ approving.host?.user || '—' }}
            · 终端 IP {{ approving.host?.ip || '未上报' }}{{ approving.host?.mac ? ' · MAC ' + approving.host.mac : '' }}</div>
        </div>
        <el-form label-width="90px" size="small" class="mt-10" @submit.prevent>
          <el-form-item label="设备 ID"><el-input v-model="approveForm.device_id" maxlength="48"
                        placeholder="字母、数字、. _ -，最长 48 位"></el-input></el-form-item>
          <el-form-item label="用户"><el-input v-model="approveForm.sub" placeholder="事件中的 actor，默认同设备 ID"></el-input></el-form-item>
          <el-form-item label="允许的 Agent">
            <el-checkbox-group v-model="approveForm.agents">
              <el-checkbox v-for="a in deviceData.agents" :key="a.agent" :value="a.agent">{{ AGENT_NAMES[a.agent] || a.agent }}</el-checkbox>
            </el-checkbox-group>
          </el-form-item>
          <el-form-item label="策略档案">
            <el-radio-group v-model="approveForm.profile">
              <el-radio-button v-for="p in deviceData.profiles" :key="p" :value="p">{{ p }}</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-alert v-if="approveError" :title="approveError" type="error" :closable="false"></el-alert>
        </el-form>
      </template>
      <template #footer>
        <el-button size="small" @click="approveOpen = false">取消</el-button>
        <el-button size="small" type="primary" :loading="saving" :disabled="!approveForm.device_id || !approveForm.agents.length"
                   @click="submitApprove">认证</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import { AGENT_NAMES } from "../../store/runtime";
import { deviceData, approveEnrollment, rejectEnrollment } from "../../store/devices";
import { short } from "./helpers";
import DeviceNetwork from "./DeviceNetwork.vue";

const saving = ref(false);
// ---- 认证待接入设备 ----
const approveOpen = ref(false);
const approving = ref(null);
const approveError = ref("");
const approveForm = reactive({ device_id: "", sub: "", agents: [], profile: "developer" });

function openApprove(row) {
  approving.value = row;
  approveError.value = "";
  Object.assign(approveForm, { device_id: row.suggested_device_id || "", sub: row.host?.user || "",
    agents: [...row.agents], profile: "developer" });
  approveOpen.value = true;
}

async function submitApprove() {
  saving.value = true;
  approveError.value = "";
  try {
    const device = await approveEnrollment(approving.value.enrollment_id, {
      device_id: approveForm.device_id.trim(), agents: approveForm.agents, profile: approveForm.profile,
      actor: { sub: approveForm.sub.trim() || approveForm.device_id.trim() },
    });
    approveOpen.value = false;
    ElMessage.success(`已认证 ${device.device_id}，终端在下一个 Hook 事件（约 30 秒内）开始生效`);
  } catch (e) {
    approveError.value = e.message;
  } finally {
    saving.value = false;
  }
}
</script>

<style scoped>
.enrollment-heading { display: flex; align-items: center; gap: 8px; margin-bottom: 0; }
</style>
