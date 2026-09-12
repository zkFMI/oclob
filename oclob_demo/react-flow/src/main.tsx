import { memo, useEffect, useMemo, useRef, type FocusEvent, type KeyboardEvent } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import {
  Background,
  BackgroundVariant,
  BaseEdge,
  Controls,
  Handle,
  MarkerType,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
  getViewportForBounds,
  useReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './network.css';
import { startNativeApp } from './native';

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
  /** Interactive graphs: `false` keeps a card clickable but out of the Tab
   *  order (member cards whose action is also listed in their group's panel). */
  focusable?: boolean;
  /** Accessible name when the visible title alone is cryptic ("M1"). */
  ariaLabel?: string;
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

type ControlsPosition = 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'top-center' | 'bottom-center';

export type OclobGraphOptions = {
  ariaLabel: string;
  phase: string;
  phaseLabel: string;
  noRoundText: string;
  legend: Array<{ type: string; label: string }>;
  legendNotes: string[];
  reducedMotion: boolean;
  // --- Graph-first page additions. All optional: the native reader keeps
  // passing the seven fields above and gets the framed layout as before.
  /** `bars` (default) frames the canvas with the phase/legend/notes bars;
   *  `overlay` drops the bars and floats a compact legend inside the canvas. */
  chrome?: 'bars' | 'overlay';
  /** Cards become buttons: click, Enter and Space call `onNodeActivate`. */
  interactive?: boolean;
  /** Card shown as the one whose panel is open. */
  selectedNodeId?: string | null;
  onNodeActivate?: (id: string, node: GraphNode) => void;
  /** Click on the empty canvas (the page closes its panel). */
  onDismiss?: () => void;
  /** Pan so this card is inside the part of the canvas not covered by a
   *  bottom sheet (`obscuredBottom` px). Zoom is kept. */
  focusNodeId?: string | null;
  obscuredBottom?: number;
  controlsPosition?: ControlsPosition;
  /** The container is sized by its own CSS (whole viewport); `render` must
   *  not assign a document height. */
  fill?: boolean;
};

type OclobNodeData = {
  graphNode: GraphNode;
  interactive: boolean;
  selected: boolean;
  onActivate?: (id: string, node: GraphNode) => void;
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

// Focusing a card that sits outside the visible pane makes the browser scroll
// the overflow:hidden ancestors, which shifts the canvas away from React
// Flow's own transform. Undo that, up to and including the graph container.
function resetFocusScroll(element: HTMLElement) {
  let parent = element.parentElement;
  while (parent) {
    if (parent.scrollTop !== 0 || parent.scrollLeft !== 0) {
      parent.scrollTop = 0;
      parent.scrollLeft = 0;
    }
    if (parent.id === 'network-graph') break;
    parent = parent.parentElement;
  }
}

const OclobNode = memo(({ data }: NodeProps<Node<OclobNodeData>>) => {
  const item = data.graphNode;
  const interactive = data.interactive && typeof data.onActivate === 'function';
  const classes = [
    'qrf-node',
    `qrf-${item.type}`,
    item.badge ? 'has-badge' : '',
    interactive ? 'is-interactive' : '',
    data.selected ? 'is-selected' : '',
    ...(item.classes ?? []),
  ]
    .filter(Boolean)
    .join(' ');
  const label = item.ariaLabel ?? [item.title, item.sub, item.badge].filter(Boolean).join(' — ');
  const activate = () => {
    if (data.onActivate) data.onActivate(item.id, item);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    activate();
  };
  const onFocus = (event: FocusEvent<HTMLElement>) => resetFocusScroll(event.currentTarget);
  return (
    <article
      className={classes}
      aria-label={label}
      data-node-id={item.id}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? (item.focusable === false ? -1 : 0) : undefined}
      aria-expanded={interactive ? data.selected : undefined}
      onClick={interactive ? activate : undefined}
      onKeyDown={interactive ? onKeyDown : undefined}
      onFocus={interactive ? onFocus : undefined}
    >
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

const FIT_OPTIONS = { padding: 0.06, maxZoom: 1, duration: 0 };

// Fit from current model geometry so responsive layout and sheet opening
// cannot race a fit against stale React Flow node measurements.
function RefitOnChange({ model, focusId, obscuredBottom }: { model: OclobGraphModel; focusId: string | null; obscuredBottom: number }) {
  const { setViewport } = useReactFlow();
  const geometry = model.nodes.map(n => [n.id, n.x, n.y, n.w, n.h].join(":")).join(";");
  const fit = useRef<() => void>(() => {});
  fit.current = () => {
    const canvas = document.querySelector<HTMLElement>('#network-graph .qrf-canvas');
    if (!canvas || !model.nodes.length) return;
    const { width, height } = canvas.getBoundingClientRect();
    if (!width || !height) return;
    const left = Math.min(...model.nodes.map(n => n.x - n.w / 2));
    const top = Math.min(...model.nodes.map(n => n.y - n.h / 2));
    const right = Math.max(...model.nodes.map(n => n.x + n.w / 2));
    const bottom = Math.max(...model.nodes.map(n => n.y + n.h / 2));
    const viewport = getViewportForBounds({ x: left, y: top, width: right - left, height: bottom - top }, width, height, 0.18, 1, 0.06);
    const node = obscuredBottom > 0 && focusId ? model.nodes.find(n => n.id === focusId) : null;
    if (node) {
      const visibleHeight = Math.max(100, height - obscuredBottom);
      viewport.zoom = Math.min(1, Math.max(viewport.zoom, 0.7));
      viewport.x = width / 2 - node.x * viewport.zoom;
      viewport.y = visibleHeight / 2 - node.y * viewport.zoom;
    }
    void setViewport(viewport, { duration: 0 });
  };
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => fit.current());
    return () => window.cancelAnimationFrame(frame);
  }, [geometry, focusId, obscuredBottom]);
  useEffect(() => {
    const canvas = document.querySelector<HTMLElement>('#network-graph .qrf-canvas');
    if (!canvas || typeof ResizeObserver === 'undefined') return;
    let frame = 0;
    const observer = new ResizeObserver(() => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => fit.current());
    });
    observer.observe(canvas);
    return () => { observer.disconnect(); window.cancelAnimationFrame(frame); };
  }, []);
  return null;
}

export function FlowCanvas({ model, options }: { model: OclobGraphModel; options: OclobGraphOptions }) {
  const interactive = Boolean(options.interactive && options.onNodeActivate);
  const overlay = options.chrome === 'overlay';
  const selectedNodeId = options.selectedNodeId ?? null;
  const onNodeActivate = options.onNodeActivate;

  const nodes = useMemo<Node[]>(() => {
    const serviceNodes = model.nodes.map((item) => ({
      id: item.id,
      type: 'oclobNode',
      position: { x: item.x - item.w / 2, y: item.y - item.h / 2 },
      style: { width: item.w, minHeight: item.h },
      data: {
        graphNode: item,
        interactive,
        selected: interactive && item.id === selectedNodeId,
        onActivate: interactive ? onNodeActivate : undefined,
      },
      // Focus and activation are handled by the card itself (see OclobNode),
      // so React Flow's own selection/focus stays off in every mode.
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
  }, [model, interactive, selectedNodeId, onNodeActivate]);

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
    <div className={`qrf-shell${overlay ? ' qrf-overlay' : ''}`}>
      {overlay ? null : (
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
      )}
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
          fitViewOptions={FIT_OPTIONS}
          nodesConnectable={false}
          nodesDraggable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          elementsSelectable={false}
          panOnDrag
          zoomOnDoubleClick={false}
          onPaneClick={options.onDismiss}
          proOptions={{ hideAttribution: false }}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.3} color="#26354b" />
          <Controls showInteractive={false} position={options.controlsPosition ?? 'bottom-right'} />
          {overlay && options.legend.length > 0 ? (
            <Panel position="bottom-center" className="qrf-legend-float" aria-label="凡例">
              {options.legend.map((item) => (
                <span className={`qrf-legend qrf-legend-${item.type}`} key={item.type}>{item.label}</span>
              ))}
            </Panel>
          ) : null}
          <RefitOnChange model={model} focusId={overlay ? options.focusNodeId ?? null : null} obscuredBottom={overlay ? options.obscuredBottom ?? 0 : 0} />
        </ReactFlow>
      </div>
      {overlay ? null : (
        <div className="qrf-footerbar">
          {options.noRoundText ? <div className="qrf-empty">{options.noRoundText}</div> : null}
          <div className="qrf-notes">
            {options.legendNotes.map((note, index) => <span key={index}>{note}</span>)}
          </div>
        </div>
      )}
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
  if (options.fill) {
    // Graph-first page: the container is the whole viewport by its own CSS.
    container.style.height = '';
  } else {
    // A phone gets a vertically reflowed model, so give it enough document
    // height to keep the graph at a readable scale instead of fitting the
    // whole topology into a single 680px viewport. The page scrolls; the
    // graph itself remains pannable and zoomable.
    container.style.height = model.W < 560
      ? `${Math.max(920, model.H + 150)}px`
      : `${Math.max(600, Math.min(720, model.H + 100))}px`;
  }
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
startNativeApp(FlowCanvas);
