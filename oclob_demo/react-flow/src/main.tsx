import { memo, useEffect, useMemo } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import {
  Background,
  BackgroundVariant,
  BaseEdge,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './network.css';

type GraphMetric = {
  label: string;
  value: string;
  fullLabel?: string;
  fullValue?: string;
  tone?: 'normal' | 'reserved' | 'muted';
};

type GraphNode = {
  id: string;
  type: string;
  x: number;
  y: number;
  w: number;
  h: number;
  title: string;
  sub?: string;
  badge?: string;
  classes?: string[];
  metrics?: GraphMetric[];
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  d: string;
  state: 'idle' | 'flow' | 'done' | 'cut';
  color: 'teal' | 'amber' | 'blue';
  own: boolean;
  particle?: boolean;
};

type GraphLabel = {
  x: number;
  y: number;
  text: string;
  strong?: boolean;
};

export type OclobGraphModel = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  labels: GraphLabel[];
  W: number;
  H: number;
};

export type OclobGraphOptions = {
  ariaLabel: string;
  phase: string;
  phaseLabel: string;
  noRoundText: string;
  legend: Array<{ type: string; label: string }>;
  legendNotes: string[];
  reducedMotion: boolean;
};

type OclobNodeData = {
  graphNode: GraphNode;
};

type OclobEdgeData = {
  path: string;
  state: GraphEdge['state'];
  color: GraphEdge['color'];
  own: boolean;
  particle: boolean;
  reducedMotion: boolean;
};

type LabelData = { text: string; strong: boolean };

const OclobNode = memo(({ data }: NodeProps<Node<OclobNodeData>>) => {
  const item = data.graphNode;
  const classes = [
    'qrf-node',
    `qrf-${item.type}`,
    item.badge ? 'has-badge' : '',
    ...(item.classes ?? []),
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <article className={classes} aria-label={[item.title, item.sub, item.badge].filter(Boolean).join(' — ')}>
      <Handle type="target" position={Position.Top} className="qrf-handle" />
      <Handle type="target" position={Position.Left} id="left-in" className="qrf-handle" />
      <header className="qrf-node-header">
        <span className="qrf-node-kind">{item.title}</span>
        {item.badge ? <span className="qrf-badge">{item.badge}</span> : null}
      </header>
      {item.sub ? <div className="qrf-node-status">{item.sub}</div> : null}
      {item.metrics?.length ? (
        <dl className="qrf-metrics">
          {item.metrics.map((metric, index) => (
            <div
              className={`qrf-metric qrf-${metric.tone ?? 'normal'}`}
              key={`${metric.label}-${index}`}
              title={`${metric.fullLabel ?? metric.label}: ${metric.fullValue ?? metric.value}`}
              aria-label={`${metric.fullLabel ?? metric.label}: ${metric.fullValue ?? metric.value}`}
            >
              <dt>{metric.label}</dt>
              <dd>{metric.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      <Handle type="source" position={Position.Bottom} className="qrf-handle" />
      <Handle type="source" position={Position.Right} id="right-out" className="qrf-handle" />
    </article>
  );
});
OclobNode.displayName = 'OclobNode';

const FlowLabel = memo(({ data }: NodeProps<Node<LabelData>>) => (
  <div className={`qrf-edge-label${data.strong ? ' strong' : ''}`}>{data.text}</div>
));
FlowLabel.displayName = 'FlowLabel';

const TransactionEdge = memo((props: EdgeProps<Edge<OclobEdgeData>>) => {
  const { id, data, markerEnd } = props;
  if (!data) return null;
  const classes = [
    'qrf-edge',
    `qrf-edge-${data.state}`,
    `qrf-edge-${data.color}`,
    data.own ? 'qrf-edge-owned' : 'qrf-edge-faint',
  ].join(' ');
  return (
    <>
      <BaseEdge id={id} path={data.path} markerEnd={markerEnd} className={classes} />
      {data.state === 'flow' && data.own && data.particle && !data.reducedMotion ? (
        <circle r="5" className={`qrf-particle qrf-particle-${data.color}`}>
          <animateMotion dur="1.35s" repeatCount="indefinite" path={data.path} />
        </circle>
      ) : null}
    </>
  );
});
TransactionEdge.displayName = 'TransactionEdge';

const nodeTypes = { oclobNode: OclobNode, flowLabel: FlowLabel };
const edgeTypes = { transaction: TransactionEdge };

function FlowCanvas({ model, options }: { model: OclobGraphModel; options: OclobGraphOptions }) {
  const nodes = useMemo<Node[]>(() => {
    const serviceNodes = model.nodes.map((item) => ({
      id: item.id,
      type: 'oclobNode',
      position: { x: item.x - item.w / 2, y: item.y - item.h / 2 },
      style: { width: item.w, minHeight: item.h },
      data: { graphNode: item },
      draggable: false,
      selectable: false,
      focusable: false,
    }));
    const labels = model.labels.map((label, index) => ({
      id: `flow-label-${index}`,
      type: 'flowLabel',
      position: { x: label.x - 90, y: label.y - 12 },
      style: { width: 180 },
      data: { text: label.text, strong: Boolean(label.strong) },
      draggable: false,
      selectable: false,
      focusable: false,
      connectable: false,
    }));
    return [...serviceNodes, ...labels];
  }, [model]);

  const edges = useMemo<Edge[]>(() => model.edges.map((item) => ({
    id: item.id,
    type: 'transaction',
    source: item.source,
    target: item.target,
    animated: item.state === 'flow' && !options.reducedMotion,
    markerEnd: item.state === 'cut' ? undefined : {
      type: MarkerType.ArrowClosed,
      color: item.state === 'flow'
        ? (item.color === 'teal' ? '#45d7c8' : item.color === 'amber' ? '#f5b942' : '#69a7ff')
        : '#637089',
      width: 16,
      height: 16,
    },
    data: {
      path: item.d,
      state: item.state,
      color: item.color,
      own: item.own,
      particle: Boolean(item.particle),
      reducedMotion: options.reducedMotion,
    },
  })), [model, options.reducedMotion]);

  useEffect(() => {
    const live = document.querySelector('#network-graph .react-flow__viewport');
    live?.setAttribute('aria-live', 'polite');
  }, [options.phase]);

  return (
    <div className="qrf-shell">
      <div className="qrf-topbar">
        <div className="qrf-phase-panel">
          <span className="qrf-live-dot" aria-hidden="true" />
          <span>{options.phaseLabel}</span>
        </div>
        <div className="qrf-legend-panel" aria-label="凡例">
          {options.legend.map((item) => (
            <span className={`qrf-legend qrf-legend-${item.type}`} key={item.type}>{item.label}</span>
          ))}
        </div>
      </div>
      <div className="qrf-canvas">
        <ReactFlow
          aria-label={options.ariaLabel}
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          // A four-Maker/seven-node lane needs about 0.27x at a 390px
          // viewport. Keeping the old 0.35 floor made the right-hand nodes
          // unreachable in the initial mobile overview even though fitView
          // was enabled. Users can still zoom in with the controls.
          minZoom={0.18}
          maxZoom={1.8}
          fitView
          fitViewOptions={{ padding: 0.04, maxZoom: 1 }}
          nodesConnectable={false}
          nodesDraggable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          elementsSelectable={false}
          panOnDrag
          zoomOnDoubleClick={false}
          proOptions={{ hideAttribution: false }}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.3} color="#26354b" />
          <Controls showInteractive={false} position="bottom-right" />
        </ReactFlow>
      </div>
      <div className="qrf-footerbar">
        {options.noRoundText ? <div className="qrf-empty">{options.noRoundText}</div> : null}
        <div className="qrf-notes">
          {options.legendNotes.map((note, index) => <span key={index}>{note}</span>)}
        </div>
      </div>
    </div>
  );
}

const roots = new WeakMap<HTMLElement, Root>();

function render(container: HTMLElement, model: OclobGraphModel, options: OclobGraphOptions) {
  let root = roots.get(container);
  if (!root) {
    root = createRoot(container);
    roots.set(container, root);
  }
  // A phone gets a vertically reflowed model, so give it enough document
  // height to keep the graph at a readable scale instead of fitting the whole
  // topology into a single 680px viewport. The page scrolls; the graph itself
  // remains pannable and zoomable.
  container.style.height = model.W < 560
    ? `${Math.max(920, model.H + 144)}px`
    : `${Math.max(680, Math.min(820, model.H + 160))}px`;
  root.render(
    <ReactFlowProvider>
      <FlowCanvas model={model} options={options} />
    </ReactFlowProvider>,
  );
}

declare global {
  interface Window {
    OclobNetworkGraph?: { render: typeof render };
  }
}

window.OclobNetworkGraph = { render };
