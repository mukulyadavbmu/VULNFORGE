import React, { useMemo } from 'react';
import ReactFlow, { Background, Controls, Node, Edge, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';

export const AttackGraph: React.FC<{ nodes: Record<string, any>; actions: any[] }> = ({ nodes, actions }) => {
  const { rfNodes, rfEdges } = useMemo(() => {
    const rfNodes: Node[] = [];
    const rfEdges: Edge[] = [];

    const nodesArray = Object.values(nodes || {});
    
    // Layout logic: group by authContext
    let guestY = 100;
    let authY = 100;

    nodesArray.forEach((n: any, idx) => {
      const isAuth = n.authContext !== 'guest';
      rfNodes.push({
        id: n.id,
        position: { x: isAuth ? 400 : 100, y: isAuth ? authY : guestY },
        data: { label: `${n.type.toUpperCase()}: ${new URL(n.url).pathname}` },
        style: {
          background: isAuth ? '#0D1117' : '#161B22',
          color: '#C9D1D9',
          border: `1px solid ${isAuth ? '#D29922' : '#30363D'}`,
          borderRadius: '8px',
          padding: '10px',
          fontSize: '12px'
        }
      });
      if (isAuth) authY += 80;
      else guestY += 80;
    });

    // Edges based on actions
    (actions || []).forEach((a: any) => {
      if (a.targetNodeId && nodes[a.targetNodeId]) {
        // Find if this action relates to another node. For now, link to targetNodeId from a "start" point or just show loose edges
        // Simplified: link from the first node to the targetNodeId for visual flavor if no sourceNodeId is present
        const source = nodesArray[0]?.id;
        if (source && source !== a.targetNodeId) {
          rfEdges.push({
            id: `e-${a.id}`,
            source: source,
            target: a.targetNodeId,
            label: a.actionType,
            markerEnd: { type: MarkerType.ArrowClosed, color: '#F85149' },
            style: { stroke: '#F85149' },
            animated: true
          });
        }
      }
    });

    return { rfNodes, rfEdges };
  }, [nodes, actions]);

  if (rfNodes.length === 0) {
    return <div className="flex h-full items-center justify-center text-textMuted">No attack nodes discovered yet.</div>;
  }

  return (
    <ReactFlow nodes={rfNodes} edges={rfEdges} fitView attributionPosition="bottom-right">
      <Background color="#30363D" gap={16} />
      <Controls className="bg-surface border-border fill-textMain" />
    </ReactFlow>
  );
};
