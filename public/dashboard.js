(function(){
  'use strict';
  if (!window.echarts) return;

  const el = document.getElementById('dashboardData');
  if (!el) return;

  let metrics;
  try {
    metrics = JSON.parse(el.textContent || '{}');
  } catch (e) {
    console.error('Failed to parse dashboardData JSON', e);
    return;
  }

  const baseText = '#e8ecff';
  const muted = '#aab3da';
  const border = 'rgba(40,52,94,0.8)';

  function mkChart(id){
    const node = document.getElementById(id);
    if (!node) return null;
    return echarts.init(node, null, { renderer: 'canvas' });
  }

  const donut = mkChart('traceDonut');
  if (donut){
    const trace = Number(metrics.reqTraceable || 0);
    const total = Number(metrics.reqTotal || 0);
    const miss = Math.max(0, total - trace);

    donut.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(11,16,32,0.92)',
        borderColor: border,
        textStyle: { color: baseText },
        formatter: (p) => p.marker + ' ' + p.name + ': <span style="font-family:ui-monospace">' + p.value + '</span> (' + p.percent + '%)'
      },
      series: [{
        type: 'pie',
        radius: ['62%','88%'],
        center: ['50%','52%'],
        avoidLabelOverlap: true,
        padAngle: 2,
        itemStyle: { borderRadius: 10, borderColor: 'rgba(11,16,32,0.8)', borderWidth: 2 },
        label: {
          color: baseText,
          formatter: (p) => p.percent >= 12 ? (p.name + "\n" + p.percent + "%") : ''
        },
        labelLine: { lineStyle: { color: muted } },
        data: [
          { name: 'Traceable', value: trace, itemStyle: { color: new echarts.graphic.LinearGradient(0,0,1,1,[{offset:0,color:'#22c55e'},{offset:1,color:'#06b6d4'}]) } },
          { name: 'Gaps', value: miss, itemStyle: { color: new echarts.graphic.LinearGradient(0,0,1,1,[{offset:0,color:'#fb7185'},{offset:1,color:'#f97316'}]) } }
        ]
      }],
      graphic: [{
        type: 'text',
        left: 'center',
        top: '42%',
        style: {
          text: total ? (Math.round((trace/total)*100) + '%') : '—',
          fill: baseText,
          fontSize: 34,
          fontWeight: 800
        }
      },{
        type: 'text',
        left: 'center',
        top: '60%',
        style: {
          text: 'fully traceable',
          fill: muted,
          fontSize: 12
        }
      }]
    });
  }

  const funnel = mkChart('flowFunnel');
  if (funnel){
    const steps = [
      { name: 'Requirements', value: Number(metrics.reqTotal || 0) },
      { name: 'Approved decision', value: Number(metrics.reqWithApprovedDecision || 0) },
      { name: 'Rules', value: Number(metrics.reqWithRule || 0) },
      { name: 'Tests', value: Number(metrics.reqWithTests || 0) },
      { name: 'Evidence', value: Number(metrics.reqWithEvidence || 0) },
      { name: 'Fully traceable', value: Number(metrics.reqTraceable || 0) }
    ];

    funnel.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(11,16,32,0.92)',
        borderColor: border,
        textStyle: { color: baseText },
        formatter: (p) => p.marker + ' ' + p.name + ': <span style="font-family:ui-monospace">' + p.value + '</span>'
      },
      series: [{
        type: 'funnel',
        left: '6%',
        top: 8,
        bottom: 8,
        width: '88%',
        min: 0,
        sort: 'descending',
        gap: 2,
        label: { color: baseText, fontSize: 12 },
        labelLine: { length: 10, lineStyle: { color: muted } },
        itemStyle: {
          borderColor: 'rgba(11,16,32,0.7)',
          borderWidth: 1,
          shadowBlur: 18,
          shadowColor: 'rgba(138,180,255,0.18)'
        },
        emphasis: { label: { fontWeight: 700 } },
        data: steps.map((s, i) => ({
          name: s.name,
          value: s.value,
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0,0,1,0,[
              { offset: 0, color: ['#60a5fa','#a78bfa','#22c55e','#06b6d4','#f97316','#fb7185'][i] || '#60a5fa' },
              { offset: 1, color: 'rgba(18,26,51,0.35)' }
            ])
          }
        }))
      }]
    });
  }

  const impactBar = mkChart('impactBar');
  if (impactBar){
    const entries = Object.entries(metrics.impact || {});
    const cats = entries.map(([k]) => k);
    const vals = entries.map(([,v]) => Number(v || 0));

    impactBar.setOption({
      backgroundColor: 'transparent',
      grid: { left: 28, right: 18, top: 10, bottom: 30, containLabel: true },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        backgroundColor: 'rgba(11,16,32,0.92)',
        borderColor: border,
        textStyle: { color: baseText }
      },
      xAxis: {
        type: 'category',
        data: cats,
        axisLine: { lineStyle: { color: border } },
        axisTick: { show: false },
        axisLabel: { color: muted }
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: 'rgba(40,52,94,0.35)' } },
        axisLabel: { color: muted }
      },
      series: [{
        type: 'bar',
        data: vals,
        barWidth: 26,
        showBackground: true,
        backgroundStyle: { color: 'rgba(14,21,48,0.6)' },
        itemStyle: {
          borderRadius: [10,10,2,2],
          color: new echarts.graphic.LinearGradient(0,0,0,1,[
            { offset: 0, color: '#8ab4ff' },
            { offset: 1, color: '#1d4ed8' }
          ])
        },
        emphasis: { itemStyle: { shadowBlur: 16, shadowColor: 'rgba(138,180,255,0.35)' } }
      }]
    });
  }

  const charts = [donut, funnel, impactBar].filter(Boolean);
  window.addEventListener('resize', () => charts.forEach(c => c.resize()));
})();
