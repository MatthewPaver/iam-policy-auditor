import * as THREE from 'three';
import { OrbitControls } from '../assets/vendor/OrbitControls.js';

export function createWorld(mount, labels, help, onSelect) {
  const scene = new THREE.Scene();
  scene.background = new THREE.Color('#111924');
  const camera = new THREE.PerspectiveCamera(42, 1, .1, 100);
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  mount.append(renderer.domElement);
  renderer.domElement.tabIndex = 0;
  renderer.domElement.setAttribute('role', 'img');
  renderer.domElement.setAttribute('aria-label', 'Illustrative 3D permission-check scene. Drag to orbit, scroll to zoom. Arrow keys rotate; plus and minus zoom; Home resets. Written engine outcomes are below.');
  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = false; controls.enablePan = true;
  controls.minDistance = 9; controls.maxDistance = 25;
  controls.minPolarAngle = .2; controls.maxPolarAngle = Math.PI / 2.15;
  scene.add(new THREE.HemisphereLight('#d0e3ff', '#273440', 2.8));
  const light = new THREE.DirectionalLight('#ffffff', 3.2); light.position.set(-4, 10, 5); light.castShadow = true;
  light.shadow.mapSize.set(1024, 1024); light.shadow.camera.left = -10; light.shadow.camera.right = 10; light.shadow.camera.top = 8; light.shadow.camera.bottom = -8;
  scene.add(light);
  const material = color => new THREE.MeshStandardMaterial({ color, metalness: .18, roughness: .68 });
  const slate = material('#33465b'), pale = material('#91a7bb'), blue = material('#3692db'), floorMaterial = material('#18232e');
  const selectable = [], labelItems = [], gates = [], packets = [];
  let record, progress = 0, disposed = false, cameraFrame, actionFrame, finishAction, focused = 'overview';
  let motionPaused = false, pausedAt = 0, cameraStarted = 0, actionStarted = 0, cameraStep, actionStep;
  let revealed = [false, false];
  function box(parent, size, position, mat, name) {
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(...size), mat); mesh.position.set(...position); mesh.castShadow = true; mesh.receiveShadow = true;
    if (name) { mesh.userData.subject = name; selectable.push(mesh); }
    parent.add(mesh); return mesh;
  }
  box(scene, [15, .18, 10], [0, -.2, 0], floorMaterial);
  const desk = new THREE.Group(); desk.position.set(-5, 0, 0); scene.add(desk);
  box(desk, [2.2, .14, 1.3], [0, 1, 0], pale, 'reader');
  for (const x of [-.8, .8]) box(desk, [.12, 1, .8], [x, .5, 0], slate, 'reader');
  box(desk, [.18, .85, 1.1], [.25, 1.6, 0], slate, 'reader');
  box(desk, [.02, .64, .86], [.14, 1.62, 0], blue, 'reader');
  box(scene, [2.2, 1.1, 1.7], [5, .45, -2.5], slate, 'reports');
  for (let i = 0; i < 4; i++) box(scene, [1.25, .08, .9], [5, 1.1 + .13 * i, -2.5], pale, 'reports');
  const dataObjects = new THREE.Group(); scene.add(dataObjects);
  box(scene, [2.5, .2, 2.1], [5, 0, 2.5], slate, 'database');
  box(scene, [2.2, 2.5, .16], [5.7, 1.25, 2.5], slate, 'database');
  for (const z of [1.55, 3.45]) box(scene, [1.9, 2.5, .12], [5, 1.25, z], slate, 'database');
  for (let i = 0; i < 3; i++) {
    box(dataObjects, [1.9, .55, 1.65], [5, .48 + i * .72, 2.5], pale, 'database');
    box(dataObjects, [.05, .12, 1.05], [4.03, .48 + i * .72, 2.5], blue, 'database');
  }
  for (let i = 0; i < 2; i++) {
    const z = i === 0 ? -2.5 : 2.5;
    box(scene, [.5, 1.7, .45], [0, .75, z - .9], slate, 'policy');
    const pivot = new THREE.Group(); pivot.position.set(0, 1.45, z - .8); scene.add(pivot);
    const gateMaterial = material('#7d91a6'); box(pivot, [.15, .15, 1.65], [0, 0, .82], gateMaterial, 'policy'); gates.push({ pivot, material: gateMaterial });
    const path = [new THREE.Vector3(-5, .04, 0), new THREE.Vector3(-2, .04, 0), new THREE.Vector3(-1.3, .04, z), new THREE.Vector3(5, .04, z)];
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(path), new THREE.LineBasicMaterial({ color: '#627b91' })));
    const packet = box(scene, [.25, .25, .25], [-5, .45, 0], blue); packet.visible = false; packets.push(packet);
  }
  for (const [text, anchor] of [['Report reader', [-5, 2.3, 0]], ['Policy check', [0, 2.7, 0]], ['Report store', [5, 2.1, -2.5]], ['Example database', [5, 3.0, 2.5]]]) {
    const element = document.createElement('span'); element.className = 'world-label'; element.textContent = text; labels.append(element); labelItems.push({ element, anchor: new THREE.Vector3(...anchor) });
  }
  function render() {
    if (disposed || !mount.clientWidth || !mount.clientHeight) return;
    renderer.render(scene, camera);
    for (const [index, { element, anchor }] of labelItems.entries()) {
      const p = anchor.clone().project(camera), half = Math.min(mount.clientWidth / 2 - 8, element.offsetWidth / 2);
      element.style.left = `${Math.max(half + 8, Math.min(mount.clientWidth - half - 8, (p.x + 1) * mount.clientWidth / 2))}px`; element.style.top = `${(1 - p.y) * mount.clientHeight / 2}px`;
      const narrow = mount.clientWidth < 500;
      const hideOther = narrow && (focused === 'overview' ? index < 2 : index !== (focused === 'reports' ? 2 : focused === 'database' ? 3 : 1));
      if (narrow && focused === 'overview' && index === 2) element.style.top = `${(1 - p.y) * mount.clientHeight / 2 - 26}px`;
      element.hidden = hideOther || p.z < -1 || p.z > 1 || Math.abs(p.x) > .95 || Math.abs(p.y) > .95;
    }
  }
  function resize() {
    if (!mount.clientWidth || !mount.clientHeight) return;
    renderer.setSize(mount.clientWidth, mount.clientHeight, false); camera.aspect = mount.clientWidth / mount.clientHeight; camera.updateProjectionMatrix(); render();
  }
  function reset() {
    focused = 'overview';
    cancelAnimationFrame(cameraFrame);
    cameraStep = null;
    camera.position.set(-10, 10.8, 12); controls.target.set(.1, .4, 0); controls.update(); render();
  }
  function focus(subject, immediate = false) {
    focused = subject;
    cancelAnimationFrame(cameraFrame);
    if (subject === 'overview' || subject === 'reader') { reset(); return; }
    const locations = { reports: { target: [3, .8, -1.8], position: [-4, 6, 6] }, database: { target: [3, 1, 1.8], position: [-4, 5.8, 9] }, policy: { target: [0, 1, 0], position: [-6, 6, 10] } };
    const goal = locations[subject]; if (!goal) return;
    const target = new THREE.Vector3(...goal.target), position = new THREE.Vector3(...goal.position);
    const startTarget = controls.target.clone(), startPosition = camera.position.clone();
    cameraStarted = performance.now();
    function move(now) {
      if (motionPaused && !immediate) return;
      const t = immediate || matchMedia('(prefers-reduced-motion: reduce)').matches ? 1 : Math.min(1, (now - cameraStarted) / 550), k = 1 - Math.pow(1 - t, 3);
      camera.position.lerpVectors(startPosition, position, k); controls.target.lerpVectors(startTarget, target, k); controls.update(); render();
      if (t < 1 && !disposed) cameraFrame = requestAnimationFrame(move);
      else cameraStep = null;
    }
    cameraStep = move; move(cameraStarted);
  }
  function setSandbox(value) {
    revealed = [value.actions.some(action => action.task === 'report'), value.actions.some(action => action.task === 'database')];
    dataObjects.visible = Boolean(value.rows.length);
    labelItems[3].element.textContent = `Example database · ${value.rows.length} rows`;
    draw(progress);
  }
  function run(subject) {
    cancelAnimationFrame(actionFrame); finishAction?.();
    focus(subject);
    const from = subject === 'reports' ? 0 : .5, to = subject === 'reports' ? .4999 : 1;
    return new Promise(resolve => {
      let settled = false;
      const finish = (cancelled = false) => { if (settled) return; settled = true; cancelAnimationFrame(actionFrame); actionStep = null; draw(cancelled ? from : to); finishAction = null; resolve(); };
      finishAction = finish;
      if (document.hidden || matchMedia('(prefers-reduced-motion: reduce)').matches) { finish(); return; }
      actionStarted = performance.now();
      function step(now) { if (motionPaused) return; const t = Math.min(1, (now - actionStarted) / 1250); draw(from + (to - from) * t); if (t === 1 || disposed) finish(); else actionFrame = requestAnimationFrame(step); }
      actionStep = step;
      actionFrame = requestAnimationFrame(step);
    });
  }
  function draw(t) {
    progress = t;
    packets.forEach((packet, i) => {
      const result = record?.correction.result, decision = i === 0 ? result?.preservation[0].after.decision : result?.risk.candidate.decision;
      if (result && t * 2 - i >= .6) revealed[i] = true;
      gates[i].pivot.rotation.x = revealed[i] && decision === 'Allow' ? -Math.PI / 2 : 0;
      gates[i].material.color.set(!revealed[i] ? '#7d91a6' : decision === 'Allow' ? '#6ecca1' : decision === 'ConditionalAllow' ? '#f5c542' : '#d66f7f');
      mount.dataset[i === 0 ? 'reportGate' : 'databaseGate'] = revealed[i] ? decision : 'unrevealed';
      packet.visible = Boolean(result) && t > 0 && t * 2 >= i;
      if (!packet.visible) return;
      const z = i === 0 ? -2.5 : 2.5;
      const points = [new THREE.Vector3(-5, .55, 0), new THREE.Vector3(-2, .55, 0), new THREE.Vector3(-1.3, .55, z), new THREE.Vector3(decision === 'Allow' ? 4 : -.3, .55, z)];
      const lengths = points.slice(1).map((p, j) => p.distanceTo(points[j]));
      let distance = Math.max(0, Math.min(1, t * 2 - i)) * lengths.reduce((a, b) => a + b, 0);
      for (let j = 0; j < lengths.length; j++) {
        if (distance <= lengths[j] || j === lengths.length - 1) { packet.position.lerpVectors(points[j], points[j + 1], Math.min(1, distance / lengths[j])); break; }
        distance -= lengths[j];
      }
    });
    render();
  }
  function setRecord(value) {
    record = value;
    revealed = [false, false];
    gates.forEach(gate => {
      gate.pivot.rotation.x = 0;
      gate.material.color.set('#7d91a6');
    });
    draw(progress);
  }
  const onChange = () => render(); controls.addEventListener('change', onChange);
  const observer = new ResizeObserver(resize); observer.observe(mount);
  renderer.domElement.addEventListener('keydown', event => {
    if (event.key === 'Home') { event.preventDefault(); reset(); return; }
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', '+', '=', '-'].includes(event.key)) return;
    event.preventDefault();
    const spherical = new THREE.Spherical().setFromVector3(camera.position.clone().sub(controls.target));
    if (event.key === 'ArrowLeft') spherical.theta -= .15;
    if (event.key === 'ArrowRight') spherical.theta += .15;
    if (event.key === 'ArrowUp') spherical.phi = Math.max(.2, spherical.phi - .12);
    if (event.key === 'ArrowDown') spherical.phi = Math.min(Math.PI / 2.15, spherical.phi + .12);
    if (['+', '='].includes(event.key)) spherical.radius = Math.max(9, spherical.radius * .9);
    if (event.key === '-') spherical.radius = Math.min(25, spherical.radius * 1.1);
    camera.position.setFromSpherical(spherical).add(controls.target); controls.update(); render();
  });
  const ray = new THREE.Raycaster(); let down;
  renderer.domElement.addEventListener('pointerdown', event => { down = [event.clientX, event.clientY]; });
  renderer.domElement.addEventListener('pointerup', event => {
    if (!down || Math.hypot(event.clientX - down[0], event.clientY - down[1]) > 5) return;
    const rect = renderer.domElement.getBoundingClientRect(); ray.setFromCamera(new THREE.Vector2((event.clientX - rect.left) / rect.width * 2 - 1, -(event.clientY - rect.top) / rect.height * 2 + 1), camera);
    const hit = ray.intersectObjects(selectable)[0];
    const captions = { reader: 'Report reader: the same example role makes both checked requests.', policy: 'Policy check: the selected candidate determines each permission decision.', reports: 'Reports: the required request opens daily.csv.', database: 'Example database: the checked request asks to delete prod-1. Only fictional sandbox data can change.' };
    if (hit) { help.textContent = captions[hit.object.userData.subject]; onSelect?.(hit.object.userData.subject); }
  });
  renderer.domElement.addEventListener('webglcontextlost', event => { event.preventDefault(); finishAction?.(); document.dispatchEvent(new Event('policylens-graphics-lost')); });
  function pause() { if (motionPaused) return; motionPaused = true; pausedAt = performance.now(); cancelAnimationFrame(cameraFrame); cancelAnimationFrame(actionFrame); }
  function resume() {
    if (!motionPaused) return;
    const elapsed = performance.now() - pausedAt; cameraStarted += elapsed; actionStarted += elapsed; motionPaused = false;
    if (cameraStep) cameraFrame = requestAnimationFrame(cameraStep);
    if (actionStep) actionFrame = requestAnimationFrame(actionStep);
  }
  function cancel() { finishAction?.(true); cancelAnimationFrame(cameraFrame); cameraStep = null; motionPaused = false; }
  reset(); resize();
  return { setRecord, setSandbox, focus, run, draw, resize, reset, pause, resume, cancel, dispose() {
    disposed = true; cancel(); observer.disconnect(); controls.dispose(); labels.replaceChildren();
    scene.traverse(object => { object.geometry?.dispose(); if (object.material) { const materials = Array.isArray(object.material) ? object.material : [object.material]; materials.forEach(m => m.dispose()); } }); renderer.dispose();
  } };
}
