// Presentation pacing belongs here. Permission checks and sandbox effects stay in impact.js.
export function createWalkthrough({ steps, perform, motion, modeChanged, manual = false }) {
  const $ = selector => document.querySelector(selector);
  const root = $('#walkthrough'), reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let state = 'loading', index = -1, generation = 0, controller, job = Promise.resolve();
  let timer, remaining = 0, started = 0, finishDwell, visible = false;
  const gates = new Set();
  const abortError = () => new DOMException('Walkthrough cancelled', 'AbortError');
  const active = () => state === 'playing' || state === 'paused' || state === 'loading';

  function render(message) {
    root.dataset.state = state; root.dataset.step = String(index);
    const action = state === 'playing' ? 'Pause' : state === 'paused' ? 'Resume' : 'Play';
    $('#playPause').textContent = action; $('#playPause').setAttribute('aria-label', `${action} walkthrough`);
    $('#playPause').hidden = state === 'ended';
    $('#playPause').disabled = state === 'loading' || state === 'ended';
    $('#replayStory').disabled = state === 'loading';
    $('#takeControl').disabled = !active();
    $('#takeControl').hidden = state === 'ended' || state === 'manual';
    if (message) $('#playbackStatus').textContent = message;
  }
  function caption(text) {
    $('#caption').textContent = text;
    const list = $('#transcript');
    if (!list.dataset.started) { list.replaceChildren(); list.dataset.started = 'true'; }
    const li = document.createElement('li'); li.textContent = text; list.append(li);
  }
  function schedule() {
    if (state !== 'playing' || !finishDwell) return;
    started = performance.now();
    timer = setTimeout(() => { timer = null; remaining = 0; const finish = finishDwell; finishDwell = null; finish?.(); }, remaining);
  }
  function pause(reason = 'Paused. Resume when you are ready.') {
    if (state !== 'playing') return;
    if (timer) { clearTimeout(timer); timer = null; remaining = Math.max(0, remaining - (performance.now() - started)); }
    state = 'paused'; motion('pause'); render(reason);
  }
  function resume() {
    if (state !== 'paused') return;
    updateVisibility();
    if (document.hidden || !visible) { render('Bring the workspace into view, then resume.'); return; }
    state = 'playing'; motion('resume'); render('Playing once · Silent · Captions on');
    for (const release of [...gates]) release();
    schedule();
  }
  function checkpoint(signal) {
    if (signal.aborted) return Promise.reject(abortError());
    if (state === 'playing') return Promise.resolve();
    return new Promise((resolve, reject) => {
      const release = () => { cleanup(); resolve(); };
      const abort = () => { cleanup(); reject(abortError()); };
      const cleanup = () => { gates.delete(release); signal.removeEventListener('abort', abort); };
      gates.add(release); signal.addEventListener('abort', abort, { once: true });
    });
  }
  function dwell(duration, signal) {
    return new Promise((resolve, reject) => {
      const abort = () => { clearTimeout(timer); timer = null; finishDwell = null; reject(abortError()); };
      remaining = duration;
      finishDwell = () => { signal.removeEventListener('abort', abort); resolve(); };
      signal.addEventListener('abort', abort, { once: true }); schedule();
    });
  }
  const readingTime = (text, minimum) => Math.max(minimum, text.trim().split(/\s+/).length * 300 + 500);
  function cancel() { controller?.abort(); clearTimeout(timer); timer = null; finishDwell = null; motion('cancel'); }
  async function run(id, signal) {
    try {
      for (index = 0; index < steps.length; index++) {
        await checkpoint(signal);
        const step = steps[index];
        root.dataset.step = String(index); $('#chapter').textContent = `${index + 1} of ${steps.length} · ${step.title}`;
        $('#storyProgress').value = index + 1;
        caption(step.intro);
        if (step.lead) await dwell(readingTime(step.intro, step.lead), signal);
        await checkpoint(signal);
        await perform(step.id, { signal, checkpoint: () => checkpoint(signal) });
        await checkpoint(signal);
        const outcome = step.outcome?.(); if (outcome) caption(outcome);
        await dwell(readingTime(outcome || step.intro, step.duration), signal);
      }
      if (id !== generation) return;
      state = 'ended'; modeChanged(false); render('Complete. Explore the result or replay.');
    } catch (error) {
      if (id !== generation || error.name === 'AbortError') return;
      state = 'manual'; modeChanged(false); render('Walkthrough stopped. Retry the example or take the tasks yourself.');
      caption('The walkthrough could not complete. No successful result is claimed. Check the error below.');
    }
  }
  async function begin() {
    const id = ++generation; cancel(); state = 'loading'; modeChanged(true); render('Preparing the walkthrough…');
    await job;
    if (id !== generation) return;
    index = -1; controller = new AbortController(); $('#transcript').replaceChildren(); delete $('#transcript').dataset.started;
    $('#storyProgress').value = 0;
    $('#caption').textContent = steps[0].intro; $('#chapter').textContent = 'Starting the proposed change';
    updateVisibility();
    state = 'playing'; render('Playing once · Silent · Captions on');
    if (reduced.matches) pause('Reduced motion is on. Press Resume to read the guided sequence.');
    else if (document.hidden || !visible) pause('Bring the workspace into view, then resume.');
    job = run(id, controller.signal);
  }
  function takeControl() {
    ++generation; cancel(); state = 'manual'; modeChanged(false); render('You are in control. Use the task button and policy choices.');
    $('#chapter').textContent = 'Manual experiment';
    $('#caption').textContent = 'Choose a policy, then try report access and database deletion.';
  }
  function updateVisibility() {
    const enough = element => {
      const rect = element.getBoundingClientRect();
      const shown = Math.max(0, Math.min(rect.bottom, innerHeight) - Math.max(rect.top, 0));
      return shown >= Math.min(rect.height, innerHeight) * .5;
    };
    visible = enough($('#caption')) && enough($('.visual'));
    if (!visible) pause('Paused while the story is out of view. Resume when ready.');
  }
  const observer = new IntersectionObserver(updateVisibility, { threshold: [0, .5] });
  updateVisibility();
  observer.observe($('.visual'));
  observer.observe($('#caption'));
  const visibility = () => { if (document.hidden) pause('Paused while this tab is hidden. Resume when ready.'); };
  const preferences = () => { if (reduced.matches) pause('Reduced motion is on. Resume when ready.'); };
  document.addEventListener('visibilitychange', visibility); reduced.addEventListener('change', preferences);
  window.addEventListener('scroll', updateVisibility, { passive: true }); window.addEventListener('resize', updateVisibility);
  $('#playPause').onclick = () => state === 'playing' ? pause() : state === 'paused' ? resume() : begin();
  $('#replayStory').onclick = begin; $('#takeControl').onclick = takeControl;
  if (manual) { takeControl(); render('Manual mode. Play the guide whenever you want.'); }
  else begin();
  return { get active() { return active(); }, pause, takeControl, dispose() { ++generation; cancel(); observer.disconnect(); document.removeEventListener('visibilitychange', visibility); reduced.removeEventListener('change', preferences); window.removeEventListener('scroll', updateVisibility); window.removeEventListener('resize', updateVisibility); } };
}
