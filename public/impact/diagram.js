// This short highlight follows a checked request. It does not model network timing.
export function createDiagram(root) {
  let frame, finish, tick, started = 0, pausedAt = 0, paused = false;
  function cancel() { cancelAnimationFrame(frame); finish?.(); }
  return {
    run(subject) {
      cancel();
      const target = root.querySelector(`[data-task=${subject}]`);
      target.dataset.active = 'true'; started = performance.now();
      return new Promise(resolve => {
        let settled = false;
        finish = () => { if (settled) return; settled = true; cancelAnimationFrame(frame); delete target.dataset.active; target.style.removeProperty('--request-progress'); finish = null; tick = null; resolve(); };
        tick = now => {
          if (paused) return;
          const progress = Math.min(1, (now - started) / 650);
          target.style.setProperty('--request-progress', progress);
          if (progress === 1) finish(); else frame = requestAnimationFrame(tick);
        };
        frame = requestAnimationFrame(tick);
      });
    },
    pause() { if (paused) return; paused = true; pausedAt = performance.now(); cancelAnimationFrame(frame); },
    resume() { if (!paused) return; started += performance.now() - pausedAt; paused = false; if (tick) frame = requestAnimationFrame(tick); },
    cancel() { cancel(); paused = false; },
    dispose: cancel,
  };
}
