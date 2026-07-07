(function () {
  const line = document.getElementById('bootLine');
  if (!line) return;
  const messages = [
    'INITIALIZING SENTRAMAP...',
    'CONNECTING TO CERTIFICATE LOGS...',
    'CALIBRATING RISK ENGINE...',
    'SYSTEMS ONLINE'
  ];
  let i = 0;
  line.textContent = messages[0];
  const interval = setInterval(() => {
    i++;
    if (i >= messages.length) { clearInterval(interval); return; }
    line.textContent = messages[i];
  }, 600);

  // Clean up the boot overlay from the DOM after its exit animation finishes
  // so it doesn't sit invisible-but-present over the page.
  setTimeout(() => {
    const boot = document.getElementById('bootSequence');
    if (boot) boot.remove();
  }, 3500);
})();
