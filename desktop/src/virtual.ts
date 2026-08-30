import { useCallback, useLayoutEffect, useRef, useState } from "react";

/**
 * Fixed-height row windowing. A 100,000-note vault must not put 100,000 nodes in
 * the document, so lists render only the rows the viewport can show and reserve
 * the rest as two spacer blocks.
 */
export function useVirtualWindow<T extends HTMLElement = HTMLDivElement>(count: number, rowHeight: number, overscan = 6) {
  const ref = useRef<T | null>(null);
  const [viewport, setViewport] = useState(0);
  const [offset, setOffset] = useState(0);

  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;
    const measure = () => setViewport(node.clientHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const onScroll = useCallback((event: { currentTarget: { scrollTop: number } }) => {
    setOffset(event.currentTarget.scrollTop);
  }, []);

  const visible = Math.max(1, Math.ceil(viewport / rowHeight));
  const first = Math.max(0, Math.min(Math.floor(offset / rowHeight), Math.max(0, count - visible)));
  const start = Math.max(0, first - overscan);
  const end = Math.min(count, first + visible + overscan);

  return {
    ref,
    onScroll,
    start,
    end,
    topPad: start * rowHeight,
    bottomPad: Math.max(0, (count - end) * rowHeight),
  };
}
