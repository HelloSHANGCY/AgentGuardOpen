// ECharts 按需引入：柱状图、关系图与行为基线雷达。
import * as echarts from "echarts/core";
import { BarChart, GraphChart, RadarChart } from "echarts/charts";
import { GridComponent, LegendComponent, RadarComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

echarts.use([BarChart, GraphChart, RadarChart, RadarComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

export default echarts;
