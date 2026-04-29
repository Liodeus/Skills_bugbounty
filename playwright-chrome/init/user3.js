// Injected on every page load - USER 3 (green)
(() => {
  const COLOR = '#44cc44';
  const LABEL = 'USER 3';
  const TITLE_PREFIX = '[🟢 U3]';

  const inject = () => {
    if (document.getElementById('__pwnfox__')) return;

    const bar = document.createElement('div');
    bar.id = '__pwnfox__';
    bar.style.cssText = `position:fixed;top:0;left:0;right:0;height:6px;background:${COLOR};z-index:2147483647;box-shadow:0 0 8px ${COLOR};pointer-events:none;`;

    const label = document.createElement('div');
    label.style.cssText = `position:fixed;top:6px;right:8px;background:${COLOR};color:white;font:bold 11px monospace;padding:2px 8px;border-radius:0 0 4px 4px;z-index:2147483647;pointer-events:none;letter-spacing:1px;`;
    label.textContent = LABEL;

    const root = document.documentElement || document.head || document.body;
    if (!root) return;
    root.appendChild(bar);
    root.appendChild(label);

    if (!document.title.startsWith(TITLE_PREFIX)) {
      document.title = `${TITLE_PREFIX} ${document.title}`;
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
