import { createApp } from "vue";
import ElementPlus from "element-plus";
import zhCn from "element-plus/es/locale/lang/zh-cn";
import "element-plus/dist/index.css";
// 只注册控制台实际使用的图标；新增图标需在 icons/index.js 与此处登记。
import {
  Aim, ArrowRight, BellFilled, CircleCheckFilled, CircleCloseFilled, Close, Collection, Connection, Cpu, DataAnalysis,
  DataLine, Document, Files, Folder, Link, List, Monitor, Plus, Promotion, QuestionFilled, Refresh,
  Search, SetUp, Share, Timer, TrendCharts, Upload, Warning, WarningFilled,
  Activity, Boxes, Brain, Database, Gauge, Library, Radar, ShieldCheck,
} from "./icons";

import "./styles/theme.css";
import "./styles/console.css";
import App from "./App.vue";
import ConsolePageHeader from "./components/ConsolePageHeader.vue";
import FilterToggle from "./components/FilterToggle.vue";
import "./styles/controls.css";
import "./styles/motion.css";

const icons = {
  Aim, ArrowRight, BellFilled, CircleCheckFilled, CircleCloseFilled, Close, Collection, Connection, Cpu, DataAnalysis,
  DataLine, Document, Files, Folder, Link, List, Monitor, Plus, Promotion, QuestionFilled, Refresh,
  Search, SetUp, Share, Timer, TrendCharts, Upload, Warning, WarningFilled,
  Activity, Boxes, Brain, Database, Gauge, Library, Radar, ShieldCheck,
};

const app = createApp(App);
app.use(ElementPlus, { locale: zhCn });
app.component("ConsolePageHeader", ConsolePageHeader);
app.component("FilterToggle", FilterToggle);
for (const [name, component] of Object.entries(icons)) {
  app.component(name, component);
}
app.mount("#app");
